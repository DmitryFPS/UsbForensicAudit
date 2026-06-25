using System.Management;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public sealed class LiveDeviceMerger
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

            match.IsCurrentlyConnected = true;
        }
    }

    private static List<UsbDeviceRecord> CollectLiveRecords(DateTimeOffset scanTime)
    {
        var records = new List<UsbDeviceRecord>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT PNPDeviceID, Name, Caption, Description FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%' OR PNPDeviceID LIKE 'USBSTOR%'");

            foreach (ManagementObject item in searcher.Get())
            {
                AddLiveRecord(records, item["PNPDeviceID"]?.ToString(), Read(item, "Name"), Read(item, "Caption"), Read(item, "Description"), scanTime);
            }

            using var diskSearcher = new ManagementObjectSearcher(
                "SELECT PNPDeviceID, Model, Caption FROM Win32_DiskDrive WHERE InterfaceType = 'USB'");

            foreach (ManagementObject disk in diskSearcher.Get())
            {
                AddLiveRecord(records, disk["PNPDeviceID"]?.ToString(), Read(disk, "Model"), Read(disk, "Caption"), "", scanTime);
            }
        }
        catch
        {
            // Live merge is best-effort.
        }

        return records;
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

        records.Add(record);
    }

    private static UsbDeviceRecord? FindMatch(IEnumerable<UsbDeviceRecord> existing, UsbDeviceRecord live)
    {
        foreach (var device in existing)
        {
            if (device.DeviceInstanceId.Equals(live.DeviceInstanceId, StringComparison.OrdinalIgnoreCase))
            {
                return device;
            }
        }

        foreach (var device in existing.Where(x => x.VisualCategory != "SupportArtifact"))
        {
            if (SameVidPid(device, live) && SameSerial(device, live))
            {
                return device;
            }

            if (SameVidPid(device, live) && string.IsNullOrWhiteSpace(device.Serial))
            {
                return device;
            }

            if (!string.IsNullOrWhiteSpace(device.Serial)
                && live.DeviceInstanceId.Contains(device.Serial, StringComparison.OrdinalIgnoreCase))
            {
                return device;
            }
        }

        return null;
    }

    private static bool SameVidPid(UsbDeviceRecord left, UsbDeviceRecord right)
    {
        return !string.IsNullOrWhiteSpace(left.Vid)
               && !string.IsNullOrWhiteSpace(left.Pid)
               && left.Vid.Equals(right.Vid, StringComparison.OrdinalIgnoreCase)
               && left.Pid.Equals(right.Pid, StringComparison.OrdinalIgnoreCase);
    }

    private static bool SameSerial(UsbDeviceRecord left, UsbDeviceRecord right)
    {
        if (string.IsNullOrWhiteSpace(left.Serial) || string.IsNullOrWhiteSpace(right.Serial))
        {
            return false;
        }

        return left.Serial.Equals(right.Serial, StringComparison.OrdinalIgnoreCase)
               || left.Serial.Contains(right.Serial, StringComparison.OrdinalIgnoreCase)
               || right.Serial.Contains(left.Serial, StringComparison.OrdinalIgnoreCase);
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
}
