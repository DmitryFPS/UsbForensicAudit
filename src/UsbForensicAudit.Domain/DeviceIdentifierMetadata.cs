using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public static class DeviceIdentifierMetadata
{
    private static readonly Regex VidPid = new(@"(?:^|[\\#])(?:_\?\?_)?(?:USB|HID)[\\#]VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(?=&|[\\#]|$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static (string Vid, string Pid)? Pair(string id)
    {
        var match = VidPid.Match(id);
        return match.Success ? (match.Groups[1].Value.ToUpperInvariant(), match.Groups[2].Value.ToUpperInvariant()) : null;
    }

    public static void FillMissingCodes(UsbDeviceRecord record)
    {
        var pairs = new[] { record.DeviceInstanceId }.Concat(record.IdentityAliases)
            .Select(Pair).Where(x => x.HasValue).Select(x => x!.Value).Distinct().ToArray();
        if (pairs.Length != 1)
        {
            return;
        }

        var pair = pairs[0];
        if ((record.Vid.Length > 0 && !record.Vid.Equals(pair.Vid, StringComparison.OrdinalIgnoreCase))
            || (record.Pid.Length > 0 && !record.Pid.Equals(pair.Pid, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        if (record.Vid.Length == 0)
        {
            record.Vid = pair.Vid;
        }

        if (record.Pid.Length == 0)
        {
            record.Pid = pair.Pid;
        }
    }
}
