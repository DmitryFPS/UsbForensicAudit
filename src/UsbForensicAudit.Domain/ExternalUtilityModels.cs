namespace UsbForensicAudit;

public sealed class ExternalUtilityDefinition
{
    public required string Id { get; init; }
    public required string DisplayName { get; init; }
    public required string[] ProcessNames { get; init; }
    public string Description { get; init; } = "";
}

public sealed class RunningExternalUtility
{
    public required string UtilityId { get; init; }
    public required string DisplayName { get; init; }
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public required string MainWindowTitle { get; init; }
    public bool HasMainWindow { get; init; }

    public string ListDisplay =>
        HasMainWindow
            ? $"{DisplayName} (PID {ProcessId}) — {MainWindowTitle}"
            : $"{DisplayName} (PID {ProcessId}) — окно не найдено";
}

public sealed class ExternalUtilityCapture
{
    public required string UtilityId { get; init; }
    public required string DisplayName { get; init; }
    public required int ProcessId { get; init; }
    public required string WindowTitle { get; init; }
    public required DateTimeOffset CapturedAtUtc { get; init; }
    public required IReadOnlyList<ExternalUtilitySection> Sections { get; init; }
}

public sealed class ExternalUtilitySection
{
    public required string Title { get; init; }
    public required IReadOnlyList<string> ColumnHeaders { get; init; }
    public required IReadOnlyList<ExternalUtilityRow> Rows { get; init; }
}

public sealed class ExternalUtilityRow
{
    public required string SectionTitle { get; init; }
    public required string UtilityName { get; init; }
    public required IReadOnlyDictionary<string, string> Values { get; init; }
    public string PrimaryText { get; init; } = "";
    public string AnalysisText { get; set; } = "";
    public string VerdictDisplayText { get; set; } = "—";
    public string VidPidText { get; set; } = "—";
    public string VendorProductText { get; set; } = "—";

    public string DetailsText =>
        string.Join(" | ", Values.Select(pair => $"{pair.Key}: {pair.Value}"));

    public string KeyFieldsText => ExternalUtilityRowFormatter.KeyFieldsText(this);

    public string FormattedDetailsText => ExternalUtilityRowFormatter.FormattedDetailsText(this);

    public string CopyText => ExternalUtilityRowFormatter.CopyText(this);

    public bool IsOtherTracesSection => ExternalUtilitySectionCatalog.IsOtherTracesSection(SectionTitle);
}

public sealed class HistoricalUtilityLaunch
{
    public required string ToolName { get; init; }
    public required string Source { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }
    public required string Summary { get; init; }

    public string TimestampText => DateDisplay.FormatMoscow(TimestampUtc);

    public string ListDisplay =>
        $"{TimestampText} — {ToolName} ({Source})";
}

public sealed class ExternalUtilityReportSnapshot
{
    public DateTimeOffset CapturedAtUtc { get; set; }
    public string? UtilityName { get; set; }
    public List<ExternalUtilityRow> Rows { get; } = [];
    public List<HistoricalUtilityLaunch> HistoricalLaunches { get; } = [];
}
