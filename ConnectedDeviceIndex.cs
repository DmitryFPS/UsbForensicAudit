using System.Management;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public sealed class ConnectedDeviceIndex
{
    private static readonly Regex VidPidRegex = new(@"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly HashSet<string> _connectedKeys;
    private readonly HashSet<string> _connectedVidPidPairs;

    private ConnectedDeviceIndex(HashSet<string> connectedKeys, HashSet<string> connectedVidPidPairs)
    {
        _connectedKeys = connectedKeys;
        _connectedVidPidPairs = connectedVidPidPairs;
    }

    public static ConnectedDeviceIndex Capture()
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var vidPidPairs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT PNPDeviceID FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%' OR PNPDeviceID LIKE 'USBSTOR%'");

            foreach (ManagementObject item in searcher.Get())
            {
                AddKeys(keys, vidPidPairs, item["PNPDeviceID"]?.ToString());
            }

            using var diskSearcher = new ManagementObjectSearcher(
                "SELECT PNPDeviceID FROM Win32_DiskDrive WHERE InterfaceType = 'USB'");

            foreach (ManagementObject disk in diskSearcher.Get())
            {
                AddKeys(keys, vidPidPairs, disk["PNPDeviceID"]?.ToString());
            }

            using var volumeSearcher = new ManagementObjectSearcher(
                "SELECT DeviceID, DriveType FROM Win32_LogicalDisk WHERE DriveType = 2");

            foreach (ManagementObject volume in volumeSearcher.Get())
            {
                var driveLetter = volume["DeviceID"]?.ToString();
                if (!string.IsNullOrWhiteSpace(driveLetter))
                {
                    keys.Add(Normalize(driveLetter));
                }
            }
        }
        catch
        {
            // If WMI is unavailable, enrichment falls back to event-based logic only.
        }

        return new ConnectedDeviceIndex(keys, vidPidPairs);
    }

    public bool IsConnected(UsbDeviceRecord device)
    {
        foreach (var key in BuildKeys(device))
        {
            if (_connectedKeys.Contains(key))
            {
                return true;
            }
        }

        if (!string.IsNullOrWhiteSpace(device.Vid)
            && !string.IsNullOrWhiteSpace(device.Pid)
            && _connectedVidPidPairs.Contains($"{device.Vid}:{device.Pid}"))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(device.DriveLetters))
        {
            foreach (var letter in device.DriveLetters.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (_connectedKeys.Contains(Normalize(letter)))
                {
                    return true;
                }
            }
        }

        return device.IsCurrentlyConnected;
    }

    private static IEnumerable<string> BuildKeys(UsbDeviceRecord device)
    {
        yield return Normalize(device.DeviceInstanceId);

        if (!string.IsNullOrWhiteSpace(device.Serial))
        {
            yield return Normalize(device.Serial);
            yield return Normalize(TrimInstanceSuffix(device.Serial));
        }

        if (!string.IsNullOrWhiteSpace(device.ContainerId))
        {
            yield return Normalize(device.ContainerId);
        }

        if (!string.IsNullOrWhiteSpace(device.ParentIdPrefix))
        {
            yield return Normalize(device.ParentIdPrefix);
        }

        if (!string.IsNullOrWhiteSpace(device.Vid) && !string.IsNullOrWhiteSpace(device.Pid) && !string.IsNullOrWhiteSpace(device.Serial))
        {
            yield return Normalize($@"USB\VID_{device.Vid}&PID_{device.Pid}\{device.Serial}");
            yield return Normalize($@"USBSTOR\Disk&Ven_{device.Manufacturer}&Prod_{device.Product}&Rev_{device.Revision}\{device.Serial}");
        }
    }

    private static void AddKeys(HashSet<string> keys, HashSet<string> vidPidPairs, string? pnpId)
    {
        if (string.IsNullOrWhiteSpace(pnpId))
        {
            return;
        }

        keys.Add(Normalize(pnpId));

        var lastSegment = pnpId.Contains('\\') ? pnpId[(pnpId.LastIndexOf('\\') + 1)..] : pnpId;
        keys.Add(Normalize(lastSegment));
        keys.Add(Normalize(TrimInstanceSuffix(lastSegment)));

        var vidPid = VidPidRegex.Match(pnpId);
        if (vidPid.Success)
        {
            vidPidPairs.Add($"{vidPid.Groups[1].Value.ToUpperInvariant()}:{vidPid.Groups[2].Value.ToUpperInvariant()}");
            keys.Add(Normalize($"VID_{vidPid.Groups[1].Value}&PID_{vidPid.Groups[2].Value}"));
        }
    }

    private static string Normalize(string? value)
    {
        return (value ?? "").Trim().Trim('{', '}').Replace(@"\\", @"\").ToUpperInvariant();
    }

    private static string TrimInstanceSuffix(string value)
    {
        var trimmed = value.Trim();
        return trimmed.EndsWith("&0", StringComparison.OrdinalIgnoreCase) ? trimmed[..^2] : trimmed;
    }
}
