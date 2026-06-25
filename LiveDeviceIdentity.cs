using System.Text.RegularExpressions;

namespace UsbForensicAudit;

internal static class LiveDeviceIdentity
{
    private static readonly Regex VidPidRegex = new(@"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static string NormalizeDeviceId(string deviceId)
    {
        return deviceId.Trim().Replace(@"\\", @"\").ToUpperInvariant();
    }

    public static string StableKey(string deviceId, string vid, string pid)
    {
        if (!string.IsNullOrWhiteSpace(vid) && !string.IsNullOrWhiteSpace(pid))
        {
            var serial = ExtractSerial(deviceId);
            if (!string.IsNullOrWhiteSpace(serial) && !IsGenericSerial(serial))
            {
                return $"{vid}:{pid}:{serial}".ToUpperInvariant();
            }

            return $"{vid}:{pid}".ToUpperInvariant();
        }

        return NormalizeDeviceId(deviceId);
    }

    public static string ExtractSerial(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return "";
        }

        var lastSlash = deviceId.LastIndexOf('\\');
        var serial = lastSlash >= 0 ? deviceId[(lastSlash + 1)..] : deviceId;
        return serial.EndsWith("&0", StringComparison.OrdinalIgnoreCase) ? serial[..^2] : serial;
    }

    public static (string Vid, string Pid) ExtractVidPid(string deviceId)
    {
        var match = VidPidRegex.Match(deviceId);
        return match.Success
            ? (match.Groups[1].Value.ToUpperInvariant(), match.Groups[2].Value.ToUpperInvariant())
            : ("", "");
    }

    private static bool IsGenericSerial(string serial)
    {
        return serial.Equals("0", StringComparison.OrdinalIgnoreCase)
               || serial.Equals("000000000000", StringComparison.OrdinalIgnoreCase)
               || serial.StartsWith("MSFT", StringComparison.OrdinalIgnoreCase);
    }
}
