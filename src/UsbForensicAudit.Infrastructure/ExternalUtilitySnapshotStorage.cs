using System.Text.Json;
using System.IO;

namespace UsbForensicAudit;

public static class ExternalUtilitySnapshotStorage
{
    private const string FileName = "external_utility_snapshot.json";
    private static readonly object Sync = new();

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

        var path = GetPath(dataDirectory);
        var temporaryPath = path + $".{Guid.NewGuid():N}.tmp";
        lock (Sync)
        {
            try
            {
                File.WriteAllText(
                    temporaryPath,
                    JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true }));
                File.Move(temporaryPath, path, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }
        }
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
            SnapshotDto? dto;
            lock (Sync)
            {
                dto = JsonSerializer.Deserialize<SnapshotDto>(File.ReadAllText(path));
            }
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
        catch (Exception exception)
        {
            AppLog.Error(exception, "External utility snapshot load failed");
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
