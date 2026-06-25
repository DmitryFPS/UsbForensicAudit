using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace UsbForensicAudit;

public sealed class UsbRegistryCollector
{
    private static readonly Regex VidPidRegex = new(@"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public IReadOnlyList<UsbDeviceRecord> Collect(List<string> warnings)
    {
        var records = new List<UsbDeviceRecord>();
        CollectEnumTree(@"SYSTEM\CurrentControlSet\Enum\USB", "Registry: USB", records, warnings);
        CollectEnumTree(@"SYSTEM\CurrentControlSet\Enum\USBSTOR", "Registry: USBSTOR", records, warnings);
        CollectEnumTree(@"SYSTEM\CurrentControlSet\Enum\SCSI", "Registry: SCSI", records, warnings);
        CollectEnumTree(@"SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM", "Registry: WPD/MTP", records, warnings);
        EnrichUsbStorVidPid(records);
        AddMountedDeviceEvidence(records, warnings);
        return records;
    }

    private static void CollectEnumTree(string path, string source, List<UsbDeviceRecord> records, List<string> warnings)
    {
        try
        {
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
                        RawJson = JsonSerializer.Serialize(ReadValues(instance))
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

                    records.Add(record);
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения HKLM\\{path}: {ex.Message}");
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

            var hints = mounted.GetValueNames()
                .Where(x => x.Contains(@"\DosDevices\", StringComparison.OrdinalIgnoreCase) || x.Contains("Volume", StringComparison.OrdinalIgnoreCase))
                .Take(500)
                .ToArray();

            if (hints.Length == 0)
            {
                return;
            }

            var mountedRecord = new UsbDeviceRecord
            {
                Source = "Registry: MountedDevices",
                VisualCategory = "SupportArtifact",
                UserMeaning = "Служебная запись: соответствие томов и букв дисков. Это не отдельное USB-устройство.",
                DeviceType = "VolumeMapping",
                DeviceInstanceId = @"HKLM\SYSTEM\MountedDevices",
                FriendlyName = "Mounted device mappings",
                VolumeHints = string.Join("; ", hints),
                RawJson = JsonSerializer.Serialize(hints)
            };

            records.Add(mountedRecord);
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения MountedDevices: {ex.Message}");
        }
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
            .Where(x => x.Source.Equals("Registry: USB", StringComparison.OrdinalIgnoreCase)
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
}
