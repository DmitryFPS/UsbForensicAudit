using System.Text.RegularExpressions;

namespace UsbForensicAudit;

internal static class CompactVidPidParser
{
    private static readonly Regex StandardVidPidRegex = new(@"VID_([0-9A-F]{4}).*?PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex CompactVidPidRegex = new(@"Vid_([0-9A-F]{4})Pid_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static (string Vid, string Pid) ExtractVidPid(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return ("", "");
        }

        var compactMatch = CompactVidPidRegex.Match(text);
        if (compactMatch.Success)
        {
            return (compactMatch.Groups[1].Value.ToUpperInvariant(), compactMatch.Groups[2].Value.ToUpperInvariant());
        }

        var standardMatch = StandardVidPidRegex.Match(text);
        if (standardMatch.Success)
        {
            return (standardMatch.Groups[1].Value.ToUpperInvariant(), standardMatch.Groups[2].Value.ToUpperInvariant());
        }

        return ("", "");
    }

    public static IEnumerable<string> BuildMatchTokens(string text)
    {
        var (vid, pid) = ExtractVidPid(text);
        if (string.IsNullOrWhiteSpace(vid) || string.IsNullOrWhiteSpace(pid))
        {
            yield break;
        }

        yield return $"VID_{vid}";
        yield return $"PID_{pid}";
        yield return $"Vid_{vid}Pid_{pid}";
        yield return $"{vid}:{pid}";
    }
}
