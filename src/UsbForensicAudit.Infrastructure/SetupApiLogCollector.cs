using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public sealed class SetupApiLogCollector
{
    private static readonly Regex SectionRegex = new(@"^>>>\s+\[(?<title>.+?)\]", RegexOptions.Compiled);
    private static readonly Regex TimeRegex = new(@"^>>>\s+Section start (?<time>.+)$", RegexOptions.Compiled);

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings)
    {
        var evidence = new List<EvidenceRecord>();
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "inf", "setupapi.dev.log");

        if (!File.Exists(path))
        {
            warnings.Add($"setupapi.dev.log не найден: {path}");
            return evidence;
        }

        try
        {
            var currentTitle = "";
            var currentTime = DateTimeOffset.UtcNow;
            var lineNumber = 0;

            foreach (var line in File.ReadLines(path))
            {
                lineNumber++;

                var section = SectionRegex.Match(line);
                if (section.Success)
                {
                    currentTitle = section.Groups["title"].Value;
                }

                var time = TimeRegex.Match(line);
                if (time.Success && DateTimeOffset.TryParse(time.Groups["time"].Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsed))
                {
                    currentTime = parsed.ToUniversalTime();
                }

                if (!ContainsUsbHint(line) && !ContainsUsbHint(currentTitle))
                {
                    continue;
                }

                var isRemoval = LooksLikeRemoval(line) || LooksLikeRemoval(currentTitle);
                evidence.Add(new EvidenceRecord
                {
                    TimestampUtc = currentTime,
                    Source = "setupapi.dev.log",
                    EvidenceCategory = isRemoval
                        ? "Отключение/удаление устройства"
                        : "Установка/инициализация устройства",
                    UserExplanation = isRemoval
                        ? "SetupAPI зафиксировал удаление или остановку USB-устройства."
                        : "SetupAPI фиксирует установку драйвера или инициализацию PnP-устройства. Это сильный источник для первого появления устройства, но не всегда последнее подключение.",
                    EventId = $"line:{lineNumber}",
                    Level = "Info",
                    DeviceHint = ExtractDeviceHint(line, currentTitle),
                    Summary = string.IsNullOrWhiteSpace(currentTitle) ? line.Trim() : currentTitle,
                    RawText = line.Trim()
                });
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения setupapi.dev.log: {ex.Message}");
        }

        return evidence;
    }

    private static bool ContainsUsbHint(string value)
    {
        return value.Contains(@"USB\", StringComparison.OrdinalIgnoreCase)
               || value.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
               || value.Contains("VID_", StringComparison.OrdinalIgnoreCase)
               || value.Contains("WPDBUSENUM", StringComparison.OrdinalIgnoreCase);
    }

    private static string ExtractDeviceHint(string line, string currentTitle)
    {
        var text = ContainsUsbHint(line) ? line : currentTitle;
        var usbIndex = text.IndexOf("USB", StringComparison.OrdinalIgnoreCase);
        if (usbIndex < 0)
        {
            return "";
        }

        var hint = text[usbIndex..].Trim();
        return hint.Length > 180 ? hint[..180] : hint;
    }

    private static bool LooksLikeRemoval(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.Contains("remove", StringComparison.OrdinalIgnoreCase)
               || value.Contains("removed", StringComparison.OrdinalIgnoreCase)
               || value.Contains("removal", StringComparison.OrdinalIgnoreCase)
               || value.Contains("uninstall", StringComparison.OrdinalIgnoreCase)
               || value.Contains("disable", StringComparison.OrdinalIgnoreCase)
               || value.Contains("stop", StringComparison.OrdinalIgnoreCase)
               || value.Contains("surprise", StringComparison.OrdinalIgnoreCase)
               || value.Contains("удал", StringComparison.OrdinalIgnoreCase)
               || value.Contains("отключ", StringComparison.OrdinalIgnoreCase)
               || value.Contains("останов", StringComparison.OrdinalIgnoreCase);
    }
}
