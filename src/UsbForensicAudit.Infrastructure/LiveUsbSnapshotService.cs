using System.Management;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public sealed class LiveUsbSnapshotService
{
    private static readonly Regex VidPidRegex = new(@"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private readonly Dictionary<string, DateTimeOffset> _firstSeenByStableKey = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<LiveUsbDevice> GetCurrentDevices()
    {
        var devicesByStableKey = new Dictionary<string, LiveUsbDevice>(StringComparer.OrdinalIgnoreCase);
        var vidPidResolver = UsbVidPidResolver.Build();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceID, Name, Caption, PNPDeviceID, Status, Description FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%' OR PNPDeviceID LIKE 'USBSTOR%'");

            foreach (ManagementObject item in searcher.Get())
            {
                var pnpId = Read(item, "PNPDeviceID");
                if (string.IsNullOrWhiteSpace(pnpId))
                {
                    continue;
                }

                AddOrUpdate(devicesByStableKey, CreateDevice(
                    pnpId,
                    FirstNotEmpty(Read(item, "Name"), Read(item, "Caption"), Read(item, "Description"), pnpId),
                    ExtractLocation(pnpId),
                    Read(item, "Status"),
                    vidPidResolver));
            }

            AddUsbDisks(devicesByStableKey, vidPidResolver);
            AddRemovableVolumes(devicesByStableKey, vidPidResolver);

            if (EndpointProtectionEnvironment.IsInstalled)
            {
                AddEndpointProtectionFilteredDevices(devicesByStableKey, vidPidResolver);
            }
        }
        catch
        {
            // По возможности; опрос повторит попытку на следующем тике.
        }

        RemoveMissingDevices(devicesByStableKey.Keys);
        return devicesByStableKey.Values
            .OrderBy(x => x.DeviceName)
            .ThenBy(x => x.DeviceId)
            .ToArray();
    }

    private void AddUsbDisks(Dictionary<string, LiveUsbDevice> devicesByStableKey, UsbVidPidResolver vidPidResolver)
    {
        using var diskSearcher = new ManagementObjectSearcher(
            "SELECT DeviceID, Model, Caption, PNPDeviceID, Status, InterfaceType FROM Win32_DiskDrive WHERE InterfaceType = 'USB'");

        foreach (ManagementObject disk in diskSearcher.Get())
        {
            var pnpId = Read(disk, "PNPDeviceID");
            if (string.IsNullOrWhiteSpace(pnpId))
            {
                continue;
            }

            AddOrUpdate(devicesByStableKey, CreateDevice(
                pnpId,
                FirstNotEmpty(Read(disk, "Model"), Read(disk, "Caption"), "USB Mass Storage"),
                "USB Mass Storage / Flash drive",
                Read(disk, "Status"),
                vidPidResolver));
        }
    }

    private void AddEndpointProtectionFilteredDevices(Dictionary<string, LiveUsbDevice> devicesByStableKey, UsbVidPidResolver vidPidResolver)
    {
        using var searcher = new ManagementObjectSearcher(
            "SELECT PNPDeviceID, Name, Caption, Status, Description, Service, PNPClass FROM Win32_PnPEntity WHERE PNPClass='DiskDrive' OR PNPClass='USB' OR Service LIKE 'Sn%' OR Name LIKE '%USB%' OR Caption LIKE '%USB%'");

        foreach (ManagementObject item in searcher.Get())
        {
            var pnpId = Read(item, "PNPDeviceID");
            if (string.IsNullOrWhiteSpace(pnpId))
            {
                continue;
            }

            AddOrUpdate(devicesByStableKey, CreateDevice(
                pnpId,
                FirstNotEmpty(Read(item, "Name"), Read(item, "Caption"), Read(item, "Description"), pnpId),
                ExtractLocation(pnpId),
                Read(item, "Status"),
                vidPidResolver));
        }

        using var removableSearcher = new ManagementObjectSearcher(
            "SELECT PNPDeviceID, Model, Caption, Status, InterfaceType, MediaType FROM Win32_DiskDrive WHERE MediaType='Removable Media' OR MediaType='External hard disk media'");

        foreach (ManagementObject disk in removableSearcher.Get())
        {
            var pnpId = Read(disk, "PNPDeviceID");
            if (string.IsNullOrWhiteSpace(pnpId))
            {
                continue;
            }

            AddOrUpdate(devicesByStableKey, CreateDevice(
                pnpId,
                FirstNotEmpty(Read(disk, "Model"), Read(disk, "Caption"), "Съёмный накопитель"),
                "Съёмный накопитель",
                Read(disk, "Status"),
                vidPidResolver));
        }
    }

    private void AddRemovableVolumes(Dictionary<string, LiveUsbDevice> devicesByStableKey, UsbVidPidResolver vidPidResolver)
    {
        using var volumeSearcher = new ManagementObjectSearcher(
            "SELECT DeviceID, VolumeName, Description, DriveType FROM Win32_LogicalDisk WHERE DriveType = 2");

        foreach (ManagementObject volume in volumeSearcher.Get())
        {
            var driveLetter = Read(volume, "DeviceID");
            if (string.IsNullOrWhiteSpace(driveLetter))
            {
                continue;
            }

            var pnpId = ResolveVolumePnpId(driveLetter) ?? $@"REMOVABLE\{driveLetter}";
            var deviceName = FirstNotEmpty(Read(volume, "VolumeName"), Read(volume, "Description"), $"Съёмный диск {driveLetter}");
            AddOrUpdate(devicesByStableKey, CreateDevice(
                pnpId,
                deviceName,
                $"Съёмный том {driveLetter}",
                "OK",
                vidPidResolver));
        }
    }

    private static string? ResolveVolumePnpId(string driveLetter)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{driveLetter}'}} WHERE AssocClass=Win32_LogicalDiskToPartition");

            foreach (ManagementObject partition in searcher.Get())
            {
                using var diskSearcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partition["DeviceID"]}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition");

                foreach (ManagementObject disk in diskSearcher.Get())
                {
                    var pnpId = disk["PNPDeviceID"]?.ToString();
                    if (!string.IsNullOrWhiteSpace(pnpId))
                    {
                        return pnpId;
                    }
                }
            }
        }
        catch
        {
            // Игнорируем ошибки сопоставления под DLP-фильтрами.
        }

        return null;
    }

    private LiveUsbDevice CreateDevice(string pnpId, string deviceName, string location, string status, UsbVidPidResolver vidPidResolver)
    {
        var vidPid = ResolveVidPid(pnpId, vidPidResolver);
        if (string.IsNullOrWhiteSpace(vidPid.Vid) || string.IsNullOrWhiteSpace(vidPid.Pid))
        {
            vidPid = CompactVidPidParser.ExtractVidPid(FirstNotEmpty(deviceName, pnpId));
        }

        var stableKey = LiveDeviceIdentity.StableKey(pnpId, vidPid.Vid, vidPid.Pid);
        if (!_firstSeenByStableKey.TryGetValue(stableKey, out var firstSeen))
        {
            firstSeen = DateTimeOffset.UtcNow;
            _firstSeenByStableKey[stableKey] = firstSeen;
        }

        var metadata = LiveDeviceMetadataReader.Read(pnpId);
        return new LiveUsbDevice
        {
            ConnectedAtText = DateDisplay.FormatMoscow(firstSeen),
            DeviceName = TextSanitizer.Clean(deviceName, 260),
            DeviceId = pnpId,
            StableKey = stableKey,
            Vid = vidPid.Vid,
            Pid = vidPid.Pid,
            Manufacturer = metadata.Manufacturer,
            Product = metadata.Product,
            Revision = metadata.Revision,
            Location = location,
            Status = status
        };
    }

    private static void AddOrUpdate(Dictionary<string, LiveUsbDevice> devicesByStableKey, LiveUsbDevice device)
    {
        if (devicesByStableKey.TryGetValue(device.StableKey, out var existing))
        {
            if (Prefer(device, existing))
            {
                devicesByStableKey[device.StableKey] = device;
            }

            return;
        }

        devicesByStableKey[device.StableKey] = device;
    }

    private static bool Prefer(LiveUsbDevice candidate, LiveUsbDevice current)
    {
        var candidateScore = DeviceScore(candidate);
        var currentScore = DeviceScore(current);
        return candidateScore > currentScore;
    }

    private static int DeviceScore(LiveUsbDevice device)
    {
        var score = 0;
        if (device.DeviceId.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))
        {
            score += 4;
        }

        if (device.DeviceId.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase))
        {
            score += 2;
        }

        if (!string.IsNullOrWhiteSpace(device.Vid) && !string.IsNullOrWhiteSpace(device.Pid))
        {
            score += 2;
        }

        if (device.Status.Equals("OK", StringComparison.OrdinalIgnoreCase))
        {
            score += 1;
        }

        return score;
    }

    private void RemoveMissingDevices(IEnumerable<string> currentStableKeys)
    {
        var current = currentStableKeys.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var knownKey in _firstSeenByStableKey.Keys.ToArray())
        {
            if (!current.Contains(knownKey))
            {
                _firstSeenByStableKey.Remove(knownKey);
            }
        }
    }

    private static string Read(ManagementBaseObject item, string property)
    {
        return item.Properties[property]?.Value?.ToString() ?? "";
    }

    private static string FirstNotEmpty(params string[] values)
    {
        return values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "";
    }

    private static string ExtractLocation(string pnpId)
    {
        if (pnpId.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase))
        {
            return "USB Mass Storage";
        }

        if (pnpId.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase))
        {
            return "USB/Type-C через Windows PnP";
        }

        if (pnpId.StartsWith(@"REMOVABLE\", StringComparison.OrdinalIgnoreCase))
        {
            return "Съёмный том";
        }

        return "";
    }

    private static (string Vid, string Pid) ResolveVidPid(string pnpId, UsbVidPidResolver resolver)
    {
        var match = VidPidRegex.Match(pnpId);
        if (match.Success)
        {
            return (match.Groups[1].Value.ToUpperInvariant(), match.Groups[2].Value.ToUpperInvariant());
        }

        return resolver.Resolve(pnpId);
    }

    private sealed class UsbVidPidResolver
    {
        private readonly Dictionary<string, (string Vid, string Pid)> _byStrongKey;

        private UsbVidPidResolver(Dictionary<string, (string Vid, string Pid)> byStrongKey)
        {
            _byStrongKey = byStrongKey;
        }

        public static UsbVidPidResolver Build()
        {
            var map = new Dictionary<string, (string Vid, string Pid)>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var usbRoot = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB");
                if (usbRoot is not null)
                {
                    foreach (var family in usbRoot.GetSubKeyNames())
                    {
                        var vidPid = VidPidRegex.Match(family);
                        if (!vidPid.Success)
                        {
                            continue;
                        }

                        using var familyKey = usbRoot.OpenSubKey(family);
                        if (familyKey is null)
                        {
                            continue;
                        }

                        foreach (var instance in familyKey.GetSubKeyNames())
                        {
                            using var instanceKey = familyKey.OpenSubKey(instance);
                            var value = (vidPid.Groups[1].Value.ToUpperInvariant(), vidPid.Groups[2].Value.ToUpperInvariant());
                            Add(map, instance, value);
                            Add(map, TrimUsbInstance(instance), value);
                            Add(map, instanceKey?.GetValue("ParentIdPrefix")?.ToString(), value);
                            Add(map, instanceKey?.GetValue("ContainerID")?.ToString()?.Trim('{', '}'), value);
                        }
                    }
                }

                using var usbStorRoot = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
                if (usbStorRoot is not null)
                {
                    foreach (var family in usbStorRoot.GetSubKeyNames())
                    {
                        using var familyKey = usbStorRoot.OpenSubKey(family);
                        if (familyKey is null)
                        {
                            continue;
                        }

                        foreach (var instance in familyKey.GetSubKeyNames())
                        {
                            using var instanceKey = familyKey.OpenSubKey(instance);
                            var storageKeys = new[]
                            {
                                instance,
                                TrimUsbInstance(instance),
                                instanceKey?.GetValue("ParentIdPrefix")?.ToString(),
                                instanceKey?.GetValue("ContainerID")?.ToString()?.Trim('{', '}')
                            };

                            var resolved = storageKeys
                                .Where(x => !string.IsNullOrWhiteSpace(x))
                                .Select(x => map.TryGetValue(x!, out var value) ? value : ("", ""))
                                .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x.Item1));

                            if (!string.IsNullOrWhiteSpace(resolved.Item1))
                            {
                                Add(map, $@"USBSTOR\{family}\{instance}", resolved);
                                Add(map, instance, resolved);
                                Add(map, TrimUsbInstance(instance), resolved);
                            }
                        }
                    }
                }
            }
            catch
            {
                // Только по возможности; окно live-режима покажет устройства, даже если корреляция с реестром не удалась.
            }

            return new UsbVidPidResolver(map);
        }

        public (string Vid, string Pid) Resolve(string pnpId)
        {
            foreach (var key in new[] { pnpId, LastSegment(pnpId), TrimUsbInstance(LastSegment(pnpId)) })
            {
                if (!string.IsNullOrWhiteSpace(key) && _byStrongKey.TryGetValue(key, out var value))
                {
                    return value;
                }
            }

            return ("", "");
        }

        private static void Add(Dictionary<string, (string Vid, string Pid)> map, string? key, (string Vid, string Pid) value)
        {
            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value.Vid) || string.IsNullOrWhiteSpace(value.Pid))
            {
                return;
            }

            map[key.Trim().Trim('{', '}')] = value;
        }

        private static string LastSegment(string value)
        {
            var index = value.LastIndexOf('\\');
            return index >= 0 ? value[(index + 1)..] : value;
        }

        private static string TrimUsbInstance(string value)
        {
            var trimmed = value.Trim();
            return trimmed.EndsWith("&0", StringComparison.OrdinalIgnoreCase) ? trimmed[..^2] : trimmed;
        }
    }
}
