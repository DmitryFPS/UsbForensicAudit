using System.Text.RegularExpressions;

namespace UsbForensicAudit;

/// <summary>
/// Чистый индекс сопоставления «устройство ↔ подключено сейчас». Набор ключей подключённых
/// устройств заполняется инфраструктурной пробой (<see cref="IConnectedDeviceProbe"/>); сам
/// индекс не зависит от WMI и содержит только логику сопоставления.
/// </summary>
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

    public static ConnectedDeviceIndex Empty { get; } = new(
        new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        new HashSet<string>(StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// Строит индекс из «сырых» идентификаторов PnP и букв дисков, полученных инфраструктурой.
    /// </summary>
    public static ConnectedDeviceIndex Build(IEnumerable<string?> pnpIdentifiers, IEnumerable<string?> driveLetters)
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var vidPidPairs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pnpId in pnpIdentifiers)
        {
            AddKeys(keys, vidPidPairs, pnpId);
        }

        foreach (var driveLetter in driveLetters)
        {
            if (!string.IsNullOrWhiteSpace(driveLetter))
            {
                keys.Add(Normalize(driveLetter));
            }
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

            if (_connectedKeys.Contains(DeviceLiveMatcher.NormalizePnpId(key)))
            {
                return true;
            }
        }

        var scsiSignature = DeviceLiveMatcher.ParseScsiSignature(device.DeviceInstanceId);
        if (scsiSignature.Length > 0 && _connectedKeys.Contains(scsiSignature))
        {
            return true;
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
        keys.Add(DeviceLiveMatcher.NormalizePnpId(pnpId));

        var scsiSignature = DeviceLiveMatcher.ParseScsiSignature(pnpId);
        if (scsiSignature.Length > 0)
        {
            keys.Add(scsiSignature);
        }

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
        return DevicePathNormalizer.CanonicalDeviceId(value);
    }

    private static string TrimInstanceSuffix(string value)
    {
        var trimmed = value.Trim();
        return trimmed.EndsWith("&0", StringComparison.OrdinalIgnoreCase) ? trimmed[..^2] : trimmed;
    }
}
