using System.Text.Json;
using System.IO;

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
            .Where(x => x.EventId is "CLEANER_HINT" or "PROCESS_HINT")
            .Select(x => new
            {
                Evidence = x,
                Tool = CleanupAttribution.DetectToolFromEvidence(x)
            })
            .Where(x => CleanerToolCatalog.IsUsbForensicUtility(x.Tool))
            .OrderByDescending(x => x.Evidence.TimestampUtc)
            .Select(x => new HistoricalUtilityLaunch
            {
                ToolName = x.Tool ?? "USB-утилита",
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

public static class ExternalUtilitySnapshotStorage
{
    private const string FileName = "external_utility_snapshot.json";

    public static string GetPath(string dataDirectory) => Path.Combine(dataDirectory, FileName);

    public static void Save(string dataDirectory, ExternalUtilityReportSnapshot snapshot)
    {
        Directory.CreateDirectory(dataDirectory);
        var dto = new SnapshotDto
        {
            CapturedAtUtc = snapshot.CapturedAtUtc,
            UtilityName = snapshot.UtilityName,
            Rows = snapshot.Rows.Select(row => new RowDto
            {
                SectionTitle = row.SectionTitle,
                UtilityName = row.UtilityName,
                PrimaryText = row.PrimaryText,
                AnalysisText = row.AnalysisText,
                Values = row.Values.ToDictionary(x => x.Key, x => x.Value)
            }).ToList(),
            HistoricalLaunches = snapshot.HistoricalLaunches.Select(x => new LaunchDto
            {
                ToolName = x.ToolName,
                Source = x.Source,
                TimestampUtc = x.TimestampUtc,
                Summary = x.Summary
            }).ToList()
        };

        File.WriteAllText(GetPath(dataDirectory), JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true }));
    }

    public static ExternalUtilityReportSnapshot? Load(string dataDirectory)
    {
        var path = GetPath(dataDirectory);
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            var dto = JsonSerializer.Deserialize<SnapshotDto>(File.ReadAllText(path));
            if (dto is null)
            {
                return null;
            }

            var snapshot = new ExternalUtilityReportSnapshot
            {
                CapturedAtUtc = dto.CapturedAtUtc,
                UtilityName = dto.UtilityName
            };

            foreach (var launch in dto.HistoricalLaunches)
            {
                snapshot.HistoricalLaunches.Add(new HistoricalUtilityLaunch
                {
                    ToolName = launch.ToolName,
                    Source = launch.Source,
                    TimestampUtc = launch.TimestampUtc,
                    Summary = launch.Summary
                });
            }

            foreach (var row in dto.Rows)
            {
                snapshot.Rows.Add(new ExternalUtilityRow
                {
                    SectionTitle = row.SectionTitle,
                    UtilityName = row.UtilityName,
                    PrimaryText = row.PrimaryText,
                    AnalysisText = row.AnalysisText,
                    Values = row.Values
                });
            }

            return snapshot;
        }
        catch
        {
            return null;
        }
    }

    private sealed class SnapshotDto
    {
        public DateTimeOffset CapturedAtUtc { get; set; }
        public string? UtilityName { get; set; }
        public List<RowDto> Rows { get; set; } = [];
        public List<LaunchDto> HistoricalLaunches { get; set; } = [];
    }

    private sealed class RowDto
    {
        public string SectionTitle { get; set; } = "";
        public string UtilityName { get; set; } = "";
        public string PrimaryText { get; set; } = "";
        public string AnalysisText { get; set; } = "";
        public Dictionary<string, string> Values { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class LaunchDto
    {
        public string ToolName { get; set; } = "";
        public string Source { get; set; } = "";
        public DateTimeOffset TimestampUtc { get; set; }
        public string Summary { get; set; } = "";
    }
}
