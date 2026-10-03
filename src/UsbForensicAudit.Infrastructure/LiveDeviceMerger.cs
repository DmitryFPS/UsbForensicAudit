using System.Management;

namespace UsbForensicAudit;

public sealed class LiveDeviceMerger : ILiveDeviceMerger
{

    public void Merge(AuditResult result)
    {
        var existing = result.Devices.ToList();
        var liveRecords = CollectLiveRecords(result.StartedAtUtc, result.SourceWarnings);

        foreach (var live in liveRecords)
        {
            var match = FindMatch(existing, live);
            if (match is null)
            {
                result.Devices.Add(live);
                existing.Add(live);
                continue;
            }

            if (string.IsNullOrWhiteSpace(match.Vid) && !string.IsNullOrWhiteSpace(live.Vid))
            {
                match.Vid = live.Vid;
            }

            if (string.IsNullOrWhiteSpace(match.Pid) && !string.IsNullOrWhiteSpace(live.Pid))
            {
                match.Pid = live.Pid;
            }

            if (string.IsNullOrWhiteSpace(match.FriendlyName) && !string.IsNullOrWhiteSpace(live.FriendlyName))
            {
                match.FriendlyName = live.FriendlyName;
            }

            if (string.IsNullOrWhiteSpace(match.Manufacturer) && !string.IsNullOrWhiteSpace(live.Manufacturer))
            {
                match.Manufacturer = live.Manufacturer;
            }

            if (string.IsNullOrWhiteSpace(match.Product) && !string.IsNullOrWhiteSpace(live.Product))
            {
                match.Product = live.Product;
            }

            match.Service = FirstNotEmpty(match.Service, live.Service);
            match.HardwareIds = FirstNotEmpty(match.HardwareIds, live.HardwareIds);
            match.CompatibleIds = FirstNotEmpty(match.CompatibleIds, live.CompatibleIds);
            match.LocationInformation = FirstNotEmpty(match.LocationInformation, live.LocationInformation);
            match.LocationPaths = FirstNotEmpty(match.LocationPaths, live.LocationPaths);
            match.ParentDeviceInstanceId = FirstNotEmpty(live.ParentDeviceInstanceId, match.ParentDeviceInstanceId);
            match.ContainerId = FirstNotEmpty(live.ContainerId, match.ContainerId);
            match.ClassGuid = FirstNotEmpty(live.ClassGuid, match.ClassGuid);
            match.ConnectorType = live.ConnectorType;
            match.ConnectorProvenance = live.ConnectorProvenance;
            match.CurrentConnectionState = live.CurrentConnectionState;
            match.IsCurrentlyConnected = live.IsCurrentlyConnected;
            if (live.IsCurrentlyConnected) { ApplyLiveConnectionState(match, live, result.StartedAtUtc); }
            foreach (var volume in live.Volumes)
            {
                if (!match.Volumes.Any(x => x.DriveLetter.Equals(volume.DriveLetter, StringComparison.OrdinalIgnoreCase)
                                            && x.VolumeSerialNumber.Equals(volume.VolumeSerialNumber, StringComparison.OrdinalIgnoreCase)))
                {
                    match.Volumes.Add(volume);
                }
            }
            PopulateVolumeText(match);
        }

        DeviceTransportClassifier.ClassifyAll(result.Devices);
        DeviceIdentityGraph.Process(result.Devices);
    }

    private static List<UsbDeviceRecord> CollectLiveRecords(DateTimeOffset scanTime, List<string> warnings)
    {
        var snapshot = WindowsPnpSnapshot.Capture();
        if (snapshot.Error.Length > 0) { warnings.Add(snapshot.Error); }
        var records = LivePnpCollector.Collect(snapshot, DateTimeOffset.UtcNow);
        try { AddLiveVolumes(records); }
        catch (Exception ex) { warnings.Add("Текущие тома WMI не прочитаны: " + ex.Message); }
        return records;
    }
    private static void AddLiveVolumes(List<UsbDeviceRecord> records)
    {
        using var volumeSearcher = new ManagementObjectSearcher(
            "SELECT DeviceID, VolumeSerialNumber, VolumeName FROM Win32_LogicalDisk WHERE DriveType = 2");
        foreach (ManagementObject volume in volumeSearcher.Get())
        {
            var drive = Read(volume, "DeviceID").ToUpperInvariant();
            var pnpId = ResolveVolumePnpId(drive);
            if (string.IsNullOrWhiteSpace(drive) || string.IsNullOrWhiteSpace(pnpId))
            {
                continue;
            }

            var record = records.FirstOrDefault(x => x.DeviceInstanceId.Equals(pnpId, StringComparison.OrdinalIgnoreCase));
            if (record is null)
            {
                continue;
            }

            record.Volumes.Add(new VolumeIdentity
            {
                DriveLetter = drive,
                VolumeSerialNumber = NormalizeVolumeSerial(Read(volume, "VolumeSerialNumber")),
                Source = "Live: WMI associations",
                Confidence = "High",
                Provenance = [$"Win32_LogicalDisk {drive} -> partition -> disk PNPDeviceID {pnpId}"]
            });
            PopulateVolumeText(record);
        }
    }

    private static string ResolveVolumePnpId(string driveLetter)
    {
        try
        {
            using var partitionSearcher = new ManagementObjectSearcher(
                $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{driveLetter.Replace("'", "''", StringComparison.Ordinal)}'}} WHERE AssocClass=Win32_LogicalDiskToPartition");
            foreach (ManagementObject partition in partitionSearcher.Get())
            {
                var partitionId = Read(partition, "DeviceID").Replace("'", "''", StringComparison.Ordinal);
                using var diskSearcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partitionId}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition");
                foreach (ManagementObject disk in diskSearcher.Get())
                {
                    var pnp = Read(disk, "PNPDeviceID");
                    if (!string.IsNullOrWhiteSpace(pnp))
                    {
                        return pnp;
                    }
                }
            }
        }
        catch
        {
            // WMI associations are optional enrichment.
        }
        return "";
    }

    internal static void ApplyLiveConnectionState(UsbDeviceRecord match, UsbDeviceRecord live, DateTimeOffset scanTime)
    {
        match.IsCurrentlyConnected = true;
        var previousLastSeen = match.LastSeenUtc;
        match.LastSeenUtc = MaxNullable(match.LastSeenUtc, live.LastSeenUtc ?? scanTime);
        if (match.LastSeenUtc != previousLastSeen)
        {
            match.LastSeenProvenance = string.IsNullOrWhiteSpace(live.LastSeenProvenance)
                ? ScanProvenance(scanTime)
                : live.LastSeenProvenance;
        }

        if (!match.FirstConnectedUtc.HasValue)
        {
            match.FirstConnectedUtc = live.FirstConnectedUtc ?? scanTime;
            match.ConnectionDisplayKind = string.IsNullOrWhiteSpace(live.ConnectionDisplayKind)
                ? "LiveAtScan"
                : live.ConnectionDisplayKind;
            match.FirstConnectedProvenance = string.IsNullOrWhiteSpace(live.FirstConnectedProvenance)
                ? ScanProvenance(scanTime)
                : live.FirstConnectedProvenance;
        }

        if (string.IsNullOrWhiteSpace(match.DisconnectDisplayKind)
            || match.DisconnectDisplayKind.Equals("NotConnectedUnknown", StringComparison.OrdinalIgnoreCase))
        {
            match.DisconnectDisplayKind = "ConnectedNow";
        }

        if (string.IsNullOrWhiteSpace(match.DateConfidence)
            || match.DateConfidence.Contains("неизвестно", StringComparison.OrdinalIgnoreCase)
            || match.DateConfidence.Contains("не подключено", StringComparison.OrdinalIgnoreCase))
        {
            match.DateConfidence = !string.IsNullOrWhiteSpace(live.DateConfidence)
                ? live.DateConfidence
                : "Устройство обнаружено при текущем опросе Windows; время начала подключения неизвестно.";
        }
    }

    private static DateTimeOffset MaxNullable(DateTimeOffset? current, DateTimeOffset candidate) =>
        current.HasValue ? (current.Value > candidate ? current.Value : candidate) : candidate;

    /// <summary>
    /// Дата без указания источника читается в отчёте как установленный факт.
    /// Время сканирования — тоже наблюдение, и назвать его надо прямо.
    /// </summary>
    private static string ScanProvenance(DateTimeOffset scanTime) =>
        $"Живой опрос системы во время сканирования {DateDisplay.FormatMoscow(scanTime)}";

    internal static UsbDeviceRecord? FindMatch(IEnumerable<UsbDeviceRecord> existing, UsbDeviceRecord live)
    {
        foreach (var device in existing)
        {
            // A shared physical container may contain separate USB and Bluetooth functions.
            // Refresh only the exact node; DeviceIdentityGraph handles physical grouping later.
            if (DeviceLiveMatcher.PnpIdsMatch(device.DeviceInstanceId, live.DeviceInstanceId))
            {
                return device;
            }
        }

        return null;
    }

    private static string Read(ManagementBaseObject item, string property)
    {
        return item.Properties[property]?.Value?.ToString() ?? "";
    }

    private static string FirstNotEmpty(params string[] values)
    {
        return values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "";
    }

    private static string NormalizeVolumeSerial(string value) =>
        value.Replace("-", "", StringComparison.Ordinal).Trim().ToUpperInvariant();

    private static void PopulateVolumeText(UsbDeviceRecord record)
    {
        record.DriveLetters = string.Join(", ", record.Volumes.Select(x => x.DriveLetter)
            .Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase));
        record.VolumeHints = string.Join("; ", record.Volumes.SelectMany(x => new[]
            {
                x.VolumeSerialNumber.Length > 0 ? $"VSN={x.VolumeSerialNumber}" : "",
                x.VolumeGuid.Length > 0 ? $"Volume={x.VolumeGuid}" : ""
            })
            .Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase));
    }
}
