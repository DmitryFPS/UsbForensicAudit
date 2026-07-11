using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace UsbForensicAudit;

public sealed class UsbRegistryCollector : IUsbDeviceCollector
{
    private const string DeviceDatesPropertySet = "{83da6326-97a6-4088-9453-a1923f573b29}";
    private static readonly (string Id, string Name)[] DeviceDateProperties =
    [
        ("0064", "InstallDate"),
        ("0065", "FirstInstallDate"),
        ("0066", "LastArrivalDate"),
        ("0067", "LastRemovalDate")
    ];

    private static readonly Regex VidPidRegex = new(@"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex UsbFlagsCompactRegex = new(
        @"^([0-9A-F]{4})([0-9A-F]{4})[0-9A-F]{4}$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex UsbFlagsSuffixRegex = new(
        @"([0-9A-F]{4})([0-9A-F]{4})$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public string ProgressMessage => "Чтение Registry USB/USBSTOR/SCSI/WPD/usbflags...";

    public IReadOnlyList<UsbDeviceRecord> Collect(List<string> warnings)
    {
        var records = new List<UsbDeviceRecord>();
        var controlSets = GetControlSetNames(warnings);
        foreach (var path in UsbRegistryForensicHelpers.BuildControlSetEnumPaths(controlSets, "USB"))
        {
            CollectEnumTree(path, "Registry: USB", records, warnings);
        }

        foreach (var path in UsbRegistryForensicHelpers.BuildControlSetEnumPaths(controlSets, "USBSTOR"))
        {
            CollectEnumTree(path, "Registry: USBSTOR", records, warnings);
        }

        foreach (var path in UsbRegistryForensicHelpers.BuildControlSetEnumPaths(controlSets, "SCSI"))
        {
            CollectEnumTree(path, "Registry: SCSI", records, warnings);
        }

        foreach (var path in UsbRegistryForensicHelpers.BuildControlSetEnumPaths(controlSets, @"SWD\WPDBUSENUM"))
        {
            CollectEnumTree(path, "Registry: WPD/MTP", records, warnings);
        }

        CollectPortableDevices(records, warnings);
        records = DeduplicateEnumRecords(records);
        CorrelatePortableDevices(records);
        CollectUsbFlags(records, warnings);
        EnrichUsbStorVidPid(records);
        EnrichUsbVendorNames(records);
        AddMountedDeviceEvidence(records, warnings);
        DeviceIdentityGraph.Process(records);
        return records;
    }

    private static void CollectUsbFlags(List<UsbDeviceRecord> records, List<string> warnings)
    {
        var traces = new Dictionary<string, UsbFlagsTrace>(StringComparer.OrdinalIgnoreCase);

        foreach (var controlSet in GetControlSetNames(warnings))
        {
            var rootPath = $@"SYSTEM\{controlSet}\Control\usbflags";

            try
            {
                using var root = Registry.LocalMachine.OpenSubKey(rootPath);
                if (root is null)
                {
                    continue;
                }

                foreach (var keyName in root.GetSubKeyNames())
                {
                    if (!TryParseUsbFlagsKey(keyName, out var vid, out var pid))
                    {
                        continue;
                    }

                    var traceKey = $"{vid}|{pid}";
                    if (!traces.TryGetValue(traceKey, out var trace))
                    {
                        trace = new UsbFlagsTrace(vid, pid);
                        traces.Add(traceKey, trace);
                    }

                    var registryPath = $@"HKLM\{rootPath}\{keyName}";
                    using var flagKey = root.OpenSubKey(keyName);
                    trace.Add(
                        registryPath,
                        keyName,
                        flagKey is null ? null : RegistryKeyTimestamps.GetLastWriteUtc(flagKey),
                        flagKey is null ? [] : ReadValues(flagKey));
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Ошибка чтения HKLM\\{rootPath}: {ex.Message}");
            }
        }

        foreach (var trace in traces.Values)
        {
            var enumRecord = records.FirstOrDefault(x =>
                x.Source.Contains("Registry: USB", StringComparison.OrdinalIgnoreCase)
                && x.Vid.Equals(trace.Vid, StringComparison.OrdinalIgnoreCase)
                && x.Pid.Equals(trace.Pid, StringComparison.OrdinalIgnoreCase));
            var vendorLookup = UsbVendorDatabase.Lookup(trace.Vid, trace.Pid);
            var manufacturer = FirstNotEmpty(enumRecord?.Manufacturer, vendorLookup.VendorName);
            var product = FirstNotEmpty(enumRecord?.Product, vendorLookup.ProductName);
            var friendlyName = FirstNotEmpty(enumRecord?.FriendlyName, product);

            records.Add(new UsbDeviceRecord
            {
                Source = "Registry: usbflags",
                VisualCategory = "UsbFlagsTrace",
                UserMeaning = "Остаточный след USB-устройства в кэше usbflags. Подтверждает, что Windows сохранила VID/PID, но сам по себе не доказывает текущее подключение.",
                DeviceInstanceId = trace.RegistryPaths.First(),
                DeviceType = "USBFlags",
                Vid = trace.Vid,
                Pid = trace.Pid,
                FriendlyName = friendlyName,
                Manufacturer = manufacturer,
                Product = product,
                RegistryLastWriteUtc = trace.LastWriteUtc,
                LastSeenUtc = trace.LastWriteUtc,
                RawJson = JsonSerializer.Serialize(new
                {
                    trace.RegistryPaths,
                    trace.KeyNames,
                    trace.ValuesByPath
                })
            });
        }
    }

    internal static bool TryParseUsbFlagsKey(string keyName, out string vid, out string pid)
    {
        vid = "";
        pid = "";

        var compactMatch = UsbFlagsCompactRegex.Match(keyName);
        if (compactMatch.Success)
        {
            vid = compactMatch.Groups[1].Value.ToUpperInvariant();
            pid = compactMatch.Groups[2].Value.ToUpperInvariant();
            return true;
        }

        if (!keyName.StartsWith("Ignore", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var suffixMatch = UsbFlagsSuffixRegex.Match(keyName);
        if (!suffixMatch.Success)
        {
            return false;
        }

        vid = suffixMatch.Groups[1].Value.ToUpperInvariant();
        pid = suffixMatch.Groups[2].Value.ToUpperInvariant();
        return true;
    }

    private static IReadOnlyList<string> GetControlSetNames(List<string> warnings)
    {
        try
        {
            using var system = Registry.LocalMachine.OpenSubKey("SYSTEM");
            var names = system?.GetSubKeyNames()
                .Where(x => Regex.IsMatch(x, @"^ControlSet\d{3}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            return names is { Length: > 0 } ? names : ["CurrentControlSet"];
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка перечисления HKLM\\SYSTEM\\ControlSet*: {ex.Message}");
            return ["CurrentControlSet"];
        }
    }

    private static string FirstNotEmpty(params string?[] values) =>
        values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim() ?? "";

    private static void CollectEnumTree(string path, string source, List<UsbDeviceRecord> records, List<string> warnings)
    {
        try
        {
            var controlSet = path.Split('\\', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(1) ?? "";
            using var root = Registry.LocalMachine.OpenSubKey(path);
            if (root is null)
            {
                warnings.Add($"Источник недоступен или отсутствует: HKLM\\{path}");
                return;
            }

            foreach (var familyName in root.GetSubKeyNames())
            {
                using var family = root.OpenSubKey(familyName);
                if (family is null)
                {
                    continue;
                }

                foreach (var instanceName in family.GetSubKeyNames())
                {
                    using var instance = family.OpenSubKey(instanceName);
                    if (instance is null)
                    {
                        continue;
                    }

                    var deviceId = $"{GetEnumPrefix(source)}\\{familyName}\\{instanceName}";
                    var (dates, dateProperties) = ReadPnpDates(instance);
                    var record = new UsbDeviceRecord
                    {
                        Source = source,
                        VisualCategory = GetVisualCategory(source),
                        UserMeaning = GetUserMeaning(source),
                        DeviceInstanceId = deviceId,
                        DeviceType = GuessDeviceType(source, familyName),
                        Serial = CleanSerial(instanceName),
                        FriendlyName = ReadString(instance, "FriendlyName"),
                        Manufacturer = ReadString(instance, "Mfg"),
                        Product = ReadString(instance, "DeviceDesc"),
                        ClassGuid = ReadString(instance, "ClassGUID"),
                        Service = ReadString(instance, "Service"),
                        ContainerId = ReadString(instance, "ContainerID"),
                        ParentIdPrefix = ReadString(instance, "ParentIdPrefix"),
                        LocationInformation = ReadString(instance, "LocationInformation"),
                        LocationPaths = ReadMultiString(instance, "LocationPaths"),
                        RegistryLastWriteUtc = RegistryKeyTimestamps.GetLastWriteUtc(instance),
                        FirstConnectedUtc = dates.FirstConnectedUtc,
                        LastSeenUtc = dates.LastSeenUtc,
                        LastDisconnectedUtc = dates.LastDisconnectedUtc,
                        ConnectionDisplayKind = dates.FirstConnectedUtc.HasValue ? "PnpDevProperty" : "",
                        DisconnectDisplayKind = dates.LastDisconnectedUtc.HasValue ? "PnpDevProperty" : "",
                        DateConfidence = BuildPnpDateConfidence(dates),
                        RawJson = JsonSerializer.Serialize(new
                        {
                            RegistryPath = $@"HKLM\{path}\{familyName}\{instanceName}",
                            ControlSet = controlSet,
                            Values = ReadValues(instance),
                            PnpDevProperties = dateProperties,
                            DateProvenance = new
                            {
                                FirstConnected = dates.FirstConnectedProvenance,
                                LastSeen = dates.LastSeenProvenance,
                                LastDisconnected = dates.LastDisconnectedProvenance
                            }
                        })
                    };

                    var vidPid = VidPidRegex.Match(familyName);
                    if (vidPid.Success)
                    {
                        record.Vid = vidPid.Groups[1].Value.ToUpperInvariant();
                        record.Pid = vidPid.Groups[2].Value.ToUpperInvariant();
                    }

                    if (source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))
                    {
                        ParseUsbStorFamily(familyName, record);
                    }

                    if (source.Equals("Registry: USB", StringComparison.OrdinalIgnoreCase))
                    {
                        EnrichUsbVendorName(record);
                    }

                    records.Add(record);
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения HKLM\\{path}: {ex.Message}");
        }
    }

    private static (PnpDateSelection Dates, Dictionary<string, object?> Properties) ReadPnpDates(RegistryKey instance)
    {
        var parsed = new Dictionary<string, DateTimeOffset?>(StringComparer.OrdinalIgnoreCase);
        var provenance = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

        foreach (var (id, name) in DeviceDateProperties)
        {
            var relativePath = $@"Properties\{DeviceDatesPropertySet}\{id}";
            try
            {
                using var propertyKey = instance.OpenSubKey(relativePath);
                if (propertyKey is null)
                {
                    parsed[name] = null;
                    continue;
                }

                object? raw = propertyKey.GetValue(null, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                if (raw is null)
                {
                    raw = propertyKey.GetValueNames()
                        .Select(valueName => propertyKey.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames))
                        .FirstOrDefault(value => UsbRegistryForensicHelpers.TryParseFileTime(value, out _));
                }

                var valid = UsbRegistryForensicHelpers.TryParseFileTime(raw, out var timestamp);
                parsed[name] = valid ? timestamp : null;
                provenance[name] = new
                {
                    PropertySet = DeviceDatesPropertySet,
                    PropertyId = id,
                    RegistryPath = relativePath,
                    ParsedUtc = valid ? timestamp : (DateTimeOffset?)null,
                    RegistryKind = TryGetRegistryKind(propertyKey)
                };
            }
            catch
            {
                parsed[name] = null;
            }
        }

        return (
            UsbRegistryForensicHelpers.SelectPnpDates(
                parsed.GetValueOrDefault("InstallDate"),
                parsed.GetValueOrDefault("FirstInstallDate"),
                parsed.GetValueOrDefault("LastArrivalDate"),
                parsed.GetValueOrDefault("LastRemovalDate")),
            provenance);
    }

    private static string TryGetRegistryKind(RegistryKey key)
    {
        try
        {
            return key.GetValueKind("").ToString();
        }
        catch
        {
            return "Unknown";
        }
    }

    private static string BuildPnpDateConfidence(PnpDateSelection dates)
    {
        var sources = new[]
        {
            dates.FirstConnectedProvenance,
            dates.LastSeenProvenance,
            dates.LastDisconnectedProvenance
        }.Where(x => !string.IsNullOrWhiteSpace(x));

        var joined = string.Join(", ", sources);
        return string.IsNullOrWhiteSpace(joined)
            ? ""
            : $"Точные PnP DevProperties Windows: {joined}.";
    }

    private static void CollectPortableDevices(List<UsbDeviceRecord> records, List<string> warnings)
    {
        const string path = @"SOFTWARE\Microsoft\Windows Portable Devices\Devices";
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(path);
            if (root is null)
            {
                warnings.Add($"Источник недоступен или отсутствует: HKLM\\{path}");
                return;
            }

            foreach (var keyName in root.GetSubKeyNames())
            {
                using var deviceKey = root.OpenSubKey(keyName);
                if (deviceKey is null)
                {
                    continue;
                }

                var identityText = FirstNotEmpty(
                    ReadString(deviceKey, "DeviceInstanceId"),
                    ReadString(deviceKey, "DeviceID"),
                    keyName);
                var identity = UsbRegistryForensicHelpers.ParseWpdIdentity(identityText);
                var deviceId = string.IsNullOrWhiteSpace(identity.DeviceInstanceId)
                    ? $@"WPD\{keyName}"
                    : identity.DeviceInstanceId;

                var record = new UsbDeviceRecord
                {
                    Source = "Registry: Portable Devices",
                    VisualCategory = "RealUsb",
                    UserMeaning = "Portable/MTP устройство из основного каталога Windows Portable Devices.",
                    DeviceInstanceId = deviceId,
                    DeviceType = "Portable/MTP",
                    Serial = identity.Serial,
                    FriendlyName = FirstNotEmpty(
                        ReadString(deviceKey, "FriendlyName"),
                        ReadString(deviceKey, "Name")),
                    Manufacturer = FirstNotEmpty(
                        ReadString(deviceKey, "Manufacturer"),
                        ReadString(deviceKey, "Mfg")),
                    Product = FirstNotEmpty(
                        ReadString(deviceKey, "Description"),
                        ReadString(deviceKey, "DeviceDesc"),
                        ReadString(deviceKey, "Model")),
                    ContainerId = FirstNotEmpty(
                        ReadString(deviceKey, "ContainerId"),
                        ReadString(deviceKey, "ContainerID")),
                    RegistryLastWriteUtc = RegistryKeyTimestamps.GetLastWriteUtc(deviceKey),
                    RawJson = JsonSerializer.Serialize(new
                    {
                        RegistryPath = $@"HKLM\{path}\{keyName}",
                        IdentitySource = identityText,
                        ParsedIdentity = identity,
                        Values = ReadValues(deviceKey)
                    })
                };

                var vidPid = VidPidRegex.Match(deviceId);
                if (vidPid.Success)
                {
                    record.Vid = vidPid.Groups[1].Value.ToUpperInvariant();
                    record.Pid = vidPid.Groups[2].Value.ToUpperInvariant();
                    EnrichUsbVendorName(record);
                }

                records.Add(record);
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения HKLM\\{path}: {ex.Message}");
        }
    }

    private static List<UsbDeviceRecord> DeduplicateEnumRecords(IEnumerable<UsbDeviceRecord> records)
    {
        var result = new List<UsbDeviceRecord>();
        var byInstance = new Dictionary<string, UsbDeviceRecord>(StringComparer.OrdinalIgnoreCase);

        foreach (var record in records)
        {
            if (string.IsNullOrWhiteSpace(record.DeviceInstanceId)
                || !record.Source.StartsWith("Registry:", StringComparison.OrdinalIgnoreCase))
            {
                result.Add(record);
                continue;
            }

            var key = record.DeviceInstanceId.Trim().Replace(@"\\", @"\");
            if (!byInstance.TryGetValue(key, out var existing))
            {
                byInstance[key] = record;
                result.Add(record);
                continue;
            }

            UsbRegistryForensicHelpers.MergeRecord(existing, record);
            existing.RawJson = MergeRawJson(existing.RawJson, record.RawJson);
        }

        return result;
    }

    private static string MergeRawJson(string first, string second)
    {
        var entries = new List<JsonElement>();
        foreach (var json in new[] { first, second }.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            try
            {
                using var document = JsonDocument.Parse(json);
                if (document.RootElement.ValueKind == JsonValueKind.Object
                    && document.RootElement.TryGetProperty("MergedRegistryEvidence", out var merged)
                    && merged.ValueKind == JsonValueKind.Array)
                {
                    entries.AddRange(merged.EnumerateArray().Select(x => x.Clone()));
                }
                else
                {
                    entries.Add(document.RootElement.Clone());
                }
            }
            catch (JsonException)
            {
                entries.Add(JsonSerializer.SerializeToElement(new { Raw = json }));
            }
        }

        return JsonSerializer.Serialize(new { MergedRegistryEvidence = entries });
    }

    private static void CorrelatePortableDevices(List<UsbDeviceRecord> records)
    {
        var portable = records
            .Where(x => x.Source.Contains("Portable Devices", StringComparison.OrdinalIgnoreCase)
                        || x.Source.Contains("WPD", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var usb = records
            .Where(x => x.Source.Contains("Registry: USB", StringComparison.OrdinalIgnoreCase)
                        || x.Source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        foreach (var wpd in portable)
        {
            var match = usb.FirstOrDefault(candidate =>
                !ReferenceEquals(candidate, wpd)
                && UsbRegistryForensicHelpers.IdentitiesCorrelate(wpd, candidate));
            if (match is null)
            {
                continue;
            }

            UsbRegistryForensicHelpers.MergeRecord(wpd, match);
            UsbRegistryForensicHelpers.MergeRecord(match, wpd);
        }
    }

    private static void EnrichUsbVendorNames(IEnumerable<UsbDeviceRecord> records)
    {
        foreach (var record in records.Where(x =>
                     x.Source.Contains("Registry: USB", StringComparison.OrdinalIgnoreCase)))
        {
            EnrichUsbVendorName(record);
        }
    }

    private static void EnrichUsbVendorName(UsbDeviceRecord record)
    {
        if (string.IsNullOrWhiteSpace(record.Vid))
        {
            return;
        }

        var lookup = UsbVendorDatabase.Lookup(record.Vid, record.Pid);
        if (string.IsNullOrWhiteSpace(record.Manufacturer))
        {
            record.Manufacturer = lookup.VendorName ?? "";
        }

        if (string.IsNullOrWhiteSpace(record.Product))
        {
            record.Product = lookup.ProductName ?? "";
        }

        if (string.IsNullOrWhiteSpace(record.FriendlyName))
        {
            record.FriendlyName = record.Product;
        }
    }

    private static void AddMountedDeviceEvidence(List<UsbDeviceRecord> records, List<string> warnings)
    {
        try
        {
            using var mounted = Registry.LocalMachine.OpenSubKey(@"SYSTEM\MountedDevices");
            if (mounted is null)
            {
                warnings.Add("Источник недоступен или отсутствует: HKLM\\SYSTEM\\MountedDevices");
                return;
            }

            const int safetyLimit = 10_000;
            var allNames = mounted.GetValueNames()
                .Where(x => x.Contains(@"\DosDevices\", StringComparison.OrdinalIgnoreCase)
                            || x.Contains("Volume", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            var hints = allNames.Take(safetyLimit).ToArray();
            if (allNames.Length > safetyLimit)
            {
                warnings.Add($"MountedDevices содержит {allNames.Length} mappings; обработаны первые {safetyLimit}, остальные явно пропущены по защитному лимиту.");
            }

            if (hints.Length == 0)
            {
                return;
            }

            foreach (var valueName in hints)
            {
                var bytes = mounted.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[] ?? [];
                var volume = MountedDevicesParser.Parse(valueName, bytes);
                records.Add(new UsbDeviceRecord
                {
                    Source = "Registry: MountedDevices",
                    VisualCategory = "SupportArtifact",
                    UserMeaning = "Служебная запись: соответствие конкретного тома, диска или буквы. Это не отдельное USB-устройство.",
                    DeviceType = "VolumeMapping",
                    DeviceInstanceId = $@"HKLM\SYSTEM\MountedDevices\{valueName}",
                    FriendlyName = valueName,
                    DriveLetters = volume.DriveLetter,
                    VolumeHints = BuildVolumeHint(volume),
                    Volumes = [volume],
                    RawJson = JsonSerializer.Serialize(new
                    {
                        volume.MappingName,
                        volume.VolumeGuid,
                        volume.VolumeSerialNumber,
                        volume.DiskSignature,
                        volume.DiskId,
                        volume.PartitionOffset,
                        volume.DriveLetter,
                        volume.DevicePath,
                        RawBinaryBase64 = Convert.ToBase64String(bytes)
                    })
                });
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения MountedDevices: {ex.Message}");
        }
    }

    private static string BuildVolumeHint(VolumeIdentity volume)
    {
        return string.Join("; ", new[]
        {
            volume.VolumeGuid.Length > 0 ? $"VolumeGuid={volume.VolumeGuid}" : "",
            volume.DiskSignature.Length > 0 ? $"DiskSignature={volume.DiskSignature}" : "",
            volume.DiskId.Length > 0 ? $"DiskId={volume.DiskId}" : "",
            volume.PartitionOffset.HasValue ? $"Offset={volume.PartitionOffset}" : "",
            volume.DevicePath
        }.Where(x => x.Length > 0));
    }

    private static string ReadString(RegistryKey key, string valueName)
    {
        var value = key.GetValue(valueName);
        return value switch
        {
            string s => s,
            string[] a => string.Join("; ", a),
            _ => ""
        };
    }

    private static string ReadMultiString(RegistryKey key, string valueName)
    {
        var value = key.GetValue(valueName);
        return value switch
        {
            string[] a => string.Join("; ", a),
            string s => s,
            _ => ""
        };
    }

    private static Dictionary<string, object?> ReadValues(RegistryKey key)
    {
        var values = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in key.GetValueNames())
        {
            values[name] = key.GetValue(name);
        }

        return values;
    }

    private static string GetEnumPrefix(string source)
    {
        if (source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))
        {
            return "USBSTOR";
        }

        if (source.Contains("SCSI", StringComparison.OrdinalIgnoreCase))
        {
            return "SCSI";
        }

        if (source.Contains("WPD", StringComparison.OrdinalIgnoreCase))
        {
            return "SWD";
        }

        return "USB";
    }

    private static string GuessDeviceType(string source, string familyName)
    {
        if (source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))
        {
            return "Mass Storage";
        }

        if (source.Contains("WPD", StringComparison.OrdinalIgnoreCase))
        {
            return "Portable/MTP";
        }

        if (source.Contains("SCSI", StringComparison.OrdinalIgnoreCase))
        {
            return "SCSI/UASP Storage";
        }

        if (familyName.Contains("HID", StringComparison.OrdinalIgnoreCase))
        {
            return "HID";
        }

        return "USB";
    }

    private static string GetVisualCategory(string source)
    {
        if (source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
            || source.Equals("Registry: USB", StringComparison.OrdinalIgnoreCase)
            || source.Contains("WPD", StringComparison.OrdinalIgnoreCase))
        {
            return "RealUsb";
        }

        if (source.Contains("SCSI", StringComparison.OrdinalIgnoreCase))
        {
            return "RelatedStorage";
        }

        return "SupportArtifact";
    }

    private static string GetUserMeaning(string source)
    {
        if (source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))
        {
            return "Реальное USB Mass Storage устройство: флешка, внешний диск или кардридер.";
        }

        if (source.Equals("Registry: USB", StringComparison.OrdinalIgnoreCase))
        {
            return "Реальное USB/Type-C устройство, зарегистрированное Plug and Play.";
        }

        if (source.Contains("WPD", StringComparison.OrdinalIgnoreCase))
        {
            return "Реальное portable/MTP устройство: телефон, камера или медиаплеер.";
        }

        if (source.Contains("SCSI", StringComparison.OrdinalIgnoreCase))
        {
            return "Связанная storage-запись. Часто появляется у USB-накопителей, но сама по себе не доказывает отдельное подключение.";
        }

        return "Вспомогательный forensic-артефакт.";
    }

    private static void ParseUsbStorFamily(string familyName, UsbDeviceRecord record)
    {
        foreach (var part in familyName.Split('&'))
        {
            if (part.StartsWith("Ven_", StringComparison.OrdinalIgnoreCase))
            {
                record.Manufacturer = part[4..].Trim();
            }
            else if (part.StartsWith("Prod_", StringComparison.OrdinalIgnoreCase))
            {
                record.Product = part[5..].Trim();
            }
            else if (part.StartsWith("Rev_", StringComparison.OrdinalIgnoreCase))
            {
                record.Revision = part[4..].Trim();
            }
        }
    }

    private static void EnrichUsbStorVidPid(List<UsbDeviceRecord> records)
    {
        var usbRecords = records
            .Where(x => x.Source.Contains("Registry: USB", StringComparison.OrdinalIgnoreCase)
                        && !string.IsNullOrWhiteSpace(x.Vid)
                        && !string.IsNullOrWhiteSpace(x.Pid))
            .ToArray();

        foreach (var storage in records.Where(x => x.Source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)))
        {
            if (!string.IsNullOrWhiteSpace(storage.Vid) && !string.IsNullOrWhiteSpace(storage.Pid))
            {
                continue;
            }

            var match = usbRecords.FirstOrDefault(usb => IsSamePhysicalDevice(storage, usb));
            if (match is null)
            {
                continue;
            }

            storage.Vid = match.Vid;
            storage.Pid = match.Pid;
            if (string.IsNullOrWhiteSpace(storage.LocationInformation))
            {
                storage.LocationInformation = match.LocationInformation;
            }

            if (string.IsNullOrWhiteSpace(storage.LocationPaths))
            {
                storage.LocationPaths = match.LocationPaths;
            }
        }
    }

    private static bool IsSamePhysicalDevice(UsbDeviceRecord storage, UsbDeviceRecord usb)
    {
        var storageSerial = NormalizeKey(storage.Serial);
        var usbSerial = NormalizeKey(usb.Serial);
        if (storageSerial.Length >= 5 && usbSerial.Length >= 5 && (storageSerial.Contains(usbSerial, StringComparison.OrdinalIgnoreCase) || usbSerial.Contains(storageSerial, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(storage.ContainerId)
            && storage.ContainerId.Equals(usb.ContainerId, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(storage.ParentIdPrefix)
            && (usb.Serial.Contains(storage.ParentIdPrefix, StringComparison.OrdinalIgnoreCase)
                || usb.ParentIdPrefix.Contains(storage.ParentIdPrefix, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return false;
    }

    private static string NormalizeKey(string value)
    {
        var normalized = value.Trim().Trim('{', '}');
        return normalized.EndsWith("&0", StringComparison.OrdinalIgnoreCase) ? normalized[..^2] : normalized;
    }

    private static string CleanSerial(string instanceName)
    {
        var serial = instanceName;
        if (serial.EndsWith("&0", StringComparison.OrdinalIgnoreCase))
        {
            serial = serial[..^2];
        }

        return serial;
    }

    private sealed class UsbFlagsTrace(string vid, string pid)
    {
        public string Vid { get; } = vid;

        public string Pid { get; } = pid;

        public List<string> RegistryPaths { get; } = [];

        public List<string> KeyNames { get; } = [];

        public Dictionary<string, Dictionary<string, object?>> ValuesByPath { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        public DateTimeOffset? LastWriteUtc { get; private set; }

        public void Add(
            string registryPath,
            string keyName,
            DateTimeOffset? lastWriteUtc,
            Dictionary<string, object?> values)
        {
            RegistryPaths.Add(registryPath);
            KeyNames.Add(keyName);
            ValuesByPath[registryPath] = values;

            if (lastWriteUtc.HasValue && (!LastWriteUtc.HasValue || lastWriteUtc > LastWriteUtc))
            {
                LastWriteUtc = lastWriteUtc;
            }
        }
    }
}
