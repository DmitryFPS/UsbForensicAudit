using System.Management;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public sealed class LiveDeviceMerger : ILiveDeviceMerger
{
    private static readonly Regex VidPidRegex = new(@"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public void Merge(AuditResult result)
    {
        var existing = result.Devices.ToList();
        var liveRecords = CollectLiveRecords(result.StartedAtUtc);

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
            match.IsCurrentlyConnected = true;
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

    private static List<UsbDeviceRecord> CollectLiveRecords(DateTimeOffset scanTime)
    {
        var records = new List<UsbDeviceRecord>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT PNPDeviceID, Name, Caption, Description, Service, PNPClass FROM Win32_PnPEntity " +
                "WHERE PNPDeviceID LIKE 'USB%' OR PNPDeviceID LIKE 'USBSTOR%' OR PNPDeviceID LIKE 'SCSI%' " +
                "OR PNPDeviceID LIKE 'SWD%' OR PNPDeviceID LIKE 'USB4%' OR PNPDeviceID LIKE 'PCI%' " +
                "OR Service='uaspstor' OR Service='Usb4HostRouter' OR Service='Usb4DeviceRouter' OR Service='Usb4P2PNetAdapter'");

            foreach (ManagementObject item in searcher.Get())
            {
                var pnpId = item["PNPDeviceID"]?.ToString();
                var metadata = LiveDeviceMetadataReader.Read(pnpId ?? "");
                if (!DeviceTransportClassifier.IsRelevantLiveCandidate(
                        pnpId ?? "", Read(item, "Service"), metadata.HardwareIds, metadata.CompatibleIds,
                        metadata.LocationPaths, FirstNotEmpty(Read(item, "Name"), Read(item, "Caption"), Read(item, "Description"))))
                {
                    continue;
                }
                AddLiveRecord(records, pnpId, Read(item, "Name"), Read(item, "Caption"), Read(item, "Description"), scanTime);
            }

            using var diskSearcher = new ManagementObjectSearcher(
                "SELECT PNPDeviceID, Model, Caption, InterfaceType, MediaType FROM Win32_DiskDrive " +
                "WHERE InterfaceType='USB' OR MediaType='Removable Media' OR MediaType='External hard disk media' OR PNPDeviceID LIKE 'SCSI%'");

            foreach (ManagementObject disk in diskSearcher.Get())
            {
                var pnpId = disk["PNPDeviceID"]?.ToString() ?? "";
                var mediaType = disk["MediaType"]?.ToString() ?? "";
                var metadata = LiveDeviceMetadataReader.Read(pnpId);
                if (!DeviceTransportClassifier.IsRelevantLiveCandidate(
                        pnpId, metadata.Service, metadata.HardwareIds, metadata.CompatibleIds, metadata.LocationPaths,
                        FirstNotEmpty(Read(disk, "Model"), Read(disk, "Caption")), mediaType)
                    && !(pnpId.StartsWith(@"SCSI\", StringComparison.OrdinalIgnoreCase)
                         && (mediaType.Contains("Removable", StringComparison.OrdinalIgnoreCase)
                             || mediaType.Contains("External", StringComparison.OrdinalIgnoreCase)
                             || metadata.Service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase))))
                {
                    continue;
                }
                AddLiveRecord(records, pnpId, Read(disk, "Model"), Read(disk, "Caption"), Read(disk, "MediaType"), scanTime);
            }

            AddLiveVolumes(records);
        }
        catch
        {
            // Слияние с live-данными выполняется по возможности (без гарантий).
        }

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

    private static void AddLiveRecord(List<UsbDeviceRecord> records, string? pnpId, string name, string caption, string description, DateTimeOffset scanTime)
    {
        if (string.IsNullOrWhiteSpace(pnpId))
        {
            return;
        }

        if (records.Any(x => x.DeviceInstanceId.Equals(pnpId, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        var metadata = LiveDeviceMetadataReader.Read(pnpId);
        var vidPid = VidPidRegex.Match(pnpId);
        var record = new UsbDeviceRecord
        {
            Source = "Live: WMI",
            VisualCategory = pnpId.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase) ? "RealUsb" : "RealUsb",
            UserMeaning = pnpId.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
                ? "Реальное USB Mass Storage устройство: флешка, внешний диск или кардридер."
                : "Реальное USB/Type-C устройство, видимое системой прямо сейчас.",
            DeviceInstanceId = pnpId,
            DeviceType = pnpId.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase) ? "USBSTOR" : "USB",
            Serial = ExtractSerial(pnpId),
            FriendlyName = TextSanitizer.Clean(FirstNotEmpty(name, caption, description), 260),
            Manufacturer = metadata.Manufacturer,
            Product = metadata.Product,
            Revision = metadata.Revision,
            Service = metadata.Service,
            HardwareIds = metadata.HardwareIds,
            CompatibleIds = metadata.CompatibleIds,
            LocationInformation = metadata.LocationInformation,
            LocationPaths = metadata.LocationPaths,
            IsCurrentlyConnected = true,
            FirstConnectedUtc = scanTime,
            LastSeenUtc = scanTime,
            ConnectionDisplayKind = "LiveAtScan",
            DisconnectDisplayKind = "ConnectedNow",
            DateConfidence = "Устройство обнаружено через WMI во время сканирования. DLP может блокировать обычные журналы Windows.",
            CollectedAtUtc = scanTime
        };

        if (vidPid.Success)
        {
            record.Vid = vidPid.Groups[1].Value.ToUpperInvariant();
            record.Pid = vidPid.Groups[2].Value.ToUpperInvariant();
        }

        DeviceTransportClassifier.Classify(record);
        records.Add(record);
    }

    internal static UsbDeviceRecord? FindMatch(IEnumerable<UsbDeviceRecord> existing, UsbDeviceRecord live)
    {
        foreach (var device in existing)
        {
            if (DeviceLiveMatcher.AreLikelySameDevice(device, live))
            {
                return device;
            }
        }

        return null;
    }

    private static string ExtractSerial(string pnpId)
    {
        var lastSlash = pnpId.LastIndexOf('\\');
        var serial = lastSlash >= 0 ? pnpId[(lastSlash + 1)..] : pnpId;
        return serial.EndsWith("&0", StringComparison.OrdinalIgnoreCase) ? serial[..^2] : serial;
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
