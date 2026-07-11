namespace UsbForensicAudit;

public static class ExternalUtilityHistoryService
{
    public static IReadOnlyList<HistoricalUtilityLaunch> CollectFromAudit(AuditResult? result)
    {
        if (result is null)
        {
            return Array.Empty<HistoricalUtilityLaunch>();
        }

        return result.Evidence
            .Select(x => new
            {
                Evidence = x,
                Assessment = CleanerEvidenceClassifier.Analyze(x)
            })
            .Where(x => x.Assessment?.SupportsExecution == true
                        && CleanerToolCatalog.IsUsbForensicUtility(x.Assessment.Tool))
            .OrderByDescending(x => x.Evidence.TimestampUtc)
            .Select(x => new HistoricalUtilityLaunch
            {
                ToolName = x.Assessment?.Tool ?? "USB-утилита",
                Source = UserDisplayText.Source(x.Evidence.Source),
                TimestampUtc = x.Evidence.TimestampUtc,
                Summary = x.Evidence.SummaryText
            })
            .ToArray();
    }
}

public static class ExternalUtilityManualParser
{
    public static ExternalUtilityRow Parse(string rawLine, string? sectionTitle = null)
    {
        var raw = rawLine.Replace("\r\n", "\n").Trim();
        string[] parts;

        if (raw.Contains('\t'))
        {
            parts = raw.Split('\t');
        }
        else if (raw.Contains(" | "))
        {
            parts = raw.Split([" | "], StringSplitOptions.None);
        }
        else if (raw.Contains(';'))
        {
            parts = raw.Split(';');
        }
        else
        {
            parts = [raw];
        }

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (parts.Length == 1)
        {
            var text = TextSanitizer.NormalizeDisplay(parts[0], 4000);
            values["Текст"] = text;
        }
        else
        {
            for (var index = 0; index < parts.Length; index++)
            {
                values[$"Поле {index + 1}"] = TextSanitizer.NormalizeDisplay(parts[index].Trim(), 500);
            }
        }

        var primary = values.Values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))
                        ?? TextSanitizer.NormalizeDisplay(raw, 4000);

        return new ExternalUtilityRow
        {
            SectionTitle = string.IsNullOrWhiteSpace(sectionTitle) ? "Ручной ввод" : sectionTitle,
            UtilityName = "Ручной ввод",
            Values = values,
            PrimaryText = primary
        };
    }
}

