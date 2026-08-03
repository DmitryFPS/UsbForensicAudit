using System;
using System.Linq;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Экспорт таймлайна в CSV: заголовок, порядок по времени, RFC-4180 экранирование
/// и «схлопывание» переводов строк, чтобы одна запись оставалась одной строкой файла.
/// </summary>
public sealed class TimelineCsvExporterTests
{
    private static EvidenceRecord Evidence(string summary, DateTimeOffset when, string source = "Реестр") => new()
    {
        TimestampUtc = when,
        Source = source,
        Summary = summary
    };

    [Fact]
    public void Csv_has_header_and_one_line_per_event()
    {
        var result = new AuditResult();
        result.Evidence.Add(Evidence("первое", DateTimeOffset.Parse("2026-01-01T10:00:00Z")));
        result.Evidence.Add(Evidence("второе", DateTimeOffset.Parse("2026-01-02T10:00:00Z")));

        var lines = TimelineCsvExporter.BuildTimelineCsv(result)
            .Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        Assert.Equal(3, lines.Length); // заголовок + 2 события
        Assert.StartsWith("Время (UTC)", lines[0]);
    }

    [Fact]
    public void Events_are_sorted_by_utc_time()
    {
        var result = new AuditResult();
        result.Evidence.Add(Evidence("позже", DateTimeOffset.Parse("2026-01-05T10:00:00Z")));
        result.Evidence.Add(Evidence("раньше", DateTimeOffset.Parse("2026-01-01T10:00:00Z")));

        var csv = TimelineCsvExporter.BuildTimelineCsv(result);

        Assert.True(csv.IndexOf("раньше", StringComparison.Ordinal) < csv.IndexOf("позже", StringComparison.Ordinal));
    }

    [Fact]
    public void Field_with_comma_or_quote_is_escaped()
    {
        var result = new AuditResult();
        result.Evidence.Add(Evidence("файл \"секрет\", копия", DateTimeOffset.Parse("2026-01-01T10:00:00Z")));

        var csv = TimelineCsvExporter.BuildTimelineCsv(result);

        Assert.Contains("\"файл \"\"секрет\"\", копия\"", csv, StringComparison.Ordinal);
    }

    [Fact]
    public void Newlines_inside_value_are_flattened()
    {
        var result = new AuditResult();
        result.Evidence.Add(Evidence("строка1\r\nстрока2", DateTimeOffset.Parse("2026-01-01T10:00:00Z")));

        var lines = TimelineCsvExporter.BuildTimelineCsv(result)
            .Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        Assert.Equal(2, lines.Length);
        Assert.Contains("строка1 строка2", lines[1], StringComparison.Ordinal);
    }
}
