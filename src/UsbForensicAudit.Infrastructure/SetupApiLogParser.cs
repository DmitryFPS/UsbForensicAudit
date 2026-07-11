using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

internal static partial class SetupApiLogParser
{
    private static readonly string[] DeviceMarkers =
    [
        @"USBSTOR\", @"USB\", @"SCSI\", @"STORAGE\", @"SWD\", @"USB4\",
        "VID_", "PID_", "WPDBUSENUM", "WPD", "MTP", "PTP", "UASP", "UASPSTOR",
        "THUNDERBOLT", "Usb4HostRouter", "Usb4DeviceRouter", "Usb4P2PNetAdapter"
    ];

    public static IReadOnlyList<EvidenceRecord> Parse(TextReader reader, string sourceName, string sourcePath = "")
    {
        var result = new List<EvidenceRecord>();
        var lines = new List<string>();
        var title = "";
        var sectionNumber = 0;

        void Flush()
        {
            if (lines.Count == 0)
            {
                return;
            }

            sectionNumber++;
            var rawText = string.Join(Environment.NewLine, lines);
            var timestamp = ParseTimestamp(lines);
            if (timestamp.HasValue && ContainsDeviceMarker(rawText))
            {
                var deviceHint = ExtractDeviceHint(rawText);
                var isRemoval = LooksLikeRemoval(title) || LooksLikeRemoval(rawText);
                result.Add(new EvidenceRecord
                {
                    TimestampUtc = timestamp.Value,
                    Source = sourceName,
                    Provider = "SetupAPI",
                    Channel = "setupapi.dev.log",
                    SourceFile = sourcePath,
                    SourceRecord = sectionNumber.ToString(CultureInfo.InvariantCulture),
                    EvidenceCategory = isRemoval
                        ? "Отключение/удаление устройства"
                        : "Установка/инициализация устройства",
                    UserExplanation = isRemoval
                        ? "SetupAPI зафиксировал удаление или остановку устройства."
                        : "SetupAPI зафиксировал установку драйвера или инициализацию PnP-устройства.",
                    EventId = $"section:{sectionNumber}",
                    Level = "Info",
                    DeviceHint = deviceHint,
                    Summary = string.IsNullOrWhiteSpace(title) ? $"SetupAPI section {sectionNumber}" : title,
                    RawText = rawText
                });
            }

            lines.Clear();
            title = "";
        }

        for (var line = reader.ReadLine(); line is not null; line = reader.ReadLine())
        {
            var match = SectionHeaderRegex().Match(line);
            if (match.Success)
            {
                Flush();
                title = match.Groups["title"].Value.Trim();
            }

            if (lines.Count > 0 || match.Success)
            {
                lines.Add(line);
            }
        }

        Flush();
        return result;
    }

    private static DateTimeOffset? ParseTimestamp(IEnumerable<string> lines)
    {
        foreach (var line in lines)
        {
            var match = SectionTimeRegex().Match(line);
            if (!match.Success)
            {
                continue;
            }

            if (DateTimeOffset.TryParse(
                    match.Groups["time"].Value.Trim(),
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeLocal,
                    out var timestamp))
            {
                return timestamp.ToUniversalTime();
            }
        }

        return null;
    }

    private static bool ContainsDeviceMarker(string value)
        => DeviceMarkers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));

    private static string ExtractDeviceHint(string text)
    {
        var devicePath = DevicePathRegex().Match(text);
        if (devicePath.Success)
        {
            return Truncate(devicePath.Value.TrimEnd(',', ';', ']', ')'), 500);
        }

        var marker = DeviceMarkers
            .Select(value => (Value: value, Index: text.IndexOf(value, StringComparison.OrdinalIgnoreCase)))
            .Where(x => x.Index >= 0)
            .OrderBy(x => x.Index)
            .FirstOrDefault();
        if (marker.Index < 0 || string.IsNullOrWhiteSpace(marker.Value))
        {
            return "";
        }

        var lineEnd = text.IndexOfAny(['\r', '\n'], marker.Index);
        var value = lineEnd < 0 ? text[marker.Index..] : text[marker.Index..lineEnd];
        return Truncate(value.Trim(), 500);
    }

    private static bool LooksLikeRemoval(string value)
    {
        return value.Contains("remove", StringComparison.OrdinalIgnoreCase)
               || value.Contains("uninstall", StringComparison.OrdinalIgnoreCase)
               || value.Contains("disable", StringComparison.OrdinalIgnoreCase)
               || value.Contains("surprise", StringComparison.OrdinalIgnoreCase)
               || value.Contains("stop", StringComparison.OrdinalIgnoreCase);
    }

    private static string Truncate(string value, int length) => value.Length <= length ? value : value[..length];

    [GeneratedRegex(@"^>>>\s+\[(?<title>.+?)\]", RegexOptions.Compiled)]
    private static partial Regex SectionHeaderRegex();

    [GeneratedRegex(@"^>>>\s+Section start\s+(?<time>.+?)\s*$", RegexOptions.Compiled)]
    private static partial Regex SectionTimeRegex();

    [GeneratedRegex(@"(?i)(?:USBSTOR|USB|SCSI|STORAGE|SWD|USB4)\\[^\s\]\r\n]+")]
    private static partial Regex DevicePathRegex();
}
