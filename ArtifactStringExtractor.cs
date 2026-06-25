using System.Text;
using System.Text.RegularExpressions;
using System.IO;

namespace UsbForensicAudit;

public static class ArtifactStringExtractor
{
    private static readonly Encoding SystemAnsiEncoding = GetSystemAnsiEncoding();
    private static readonly Regex InterestingRegex = new(
        @"([A-Z]:\\[^\0\r\n]{2,220}|Volume\{[0-9A-Fa-f-]{20,}\}|USBSTOR[^\0\r\n]{0,180}|VID_[0-9A-Fa-f]{4}[^\0\r\n]{0,180}|WPDBUSENUM[^\0\r\n]{0,180})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static IReadOnlyList<string> ExtractInterestingStrings(string path, int maxBytes = 2_000_000, int maxResults = 30)
    {
        var results = new List<string>();
        try
        {
            var info = new FileInfo(path);
            var length = (int)Math.Min(info.Length, maxBytes);
            var buffer = new byte[length];
            using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            _ = stream.Read(buffer, 0, length);

            AddMatches(results, Encoding.Unicode.GetString(buffer), maxResults);
            if (results.Count < maxResults)
            {
                AddMatches(results, SystemAnsiEncoding.GetString(buffer), maxResults);
            }
        }
        catch
        {
            // Callers report file-level metadata separately; unreadable files are expected on live systems.
        }

        return results.Distinct(StringComparer.OrdinalIgnoreCase).Take(maxResults).ToArray();
    }

    public static bool LooksInteresting(string value)
    {
        return InterestingRegex.IsMatch(value);
    }

    private static void AddMatches(List<string> results, string text, int maxResults)
    {
        foreach (Match match in InterestingRegex.Matches(text))
        {
            var value = TextSanitizer.Clean(Cleanup(match.Value), 220);
            if (!TextSanitizer.IsReadableForDisplay(value))
            {
                continue;
            }

            if (value.Length > 0 && !results.Contains(value, StringComparer.OrdinalIgnoreCase))
            {
                results.Add(value);
            }

            if (results.Count >= maxResults)
            {
                return;
            }
        }
    }

    private static string Cleanup(string value)
    {
        var cleaned = new string(value.Where(ch => !char.IsControl(ch) || ch is '\\' or ':' or '{' or '}').ToArray()).Trim();
        return cleaned.Length > 220 ? cleaned[..220] : cleaned;
    }

    private static Encoding GetSystemAnsiEncoding()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        try
        {
            return Encoding.GetEncoding(1251);
        }
        catch
        {
            return Encoding.UTF8;
        }
    }
}
