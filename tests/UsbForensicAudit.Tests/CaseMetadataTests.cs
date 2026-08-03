using System;
using System.Linq;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Карточка дела: разбор JSON, только заполненные поля идут в шапку, пустая
/// карточка нейтральна, и данные дела попадают в HTML-отчёт.
/// </summary>
public sealed class CaseMetadataTests
{
    [Fact]
    public void Parse_reads_all_fields()
    {
        var meta = CaseMetadataReader.Parse("""
            { "caseNumber": "ДЕЛО-1", "examiner": "Орлов", "subject": "АРМ-5", "comment": "тест" }
            """);

        Assert.Equal("ДЕЛО-1", meta.CaseNumber);
        Assert.Equal("Орлов", meta.Examiner);
        Assert.False(meta.IsEmpty);
        Assert.Equal(4, meta.DisplayFields().Count);
    }

    [Fact]
    public void Blank_json_is_empty_case()
    {
        Assert.True(CaseMetadataReader.Parse("").IsEmpty);
        Assert.True(CaseMetadataReader.Parse("   ").IsEmpty);
    }

    [Fact]
    public void Display_fields_skip_blanks()
    {
        var meta = CaseMetadataReader.Parse("""{ "caseNumber": "ДЕЛО-9" }""");

        Assert.Single(meta.DisplayFields());
        Assert.Equal(("Дело №", "ДЕЛО-9"), meta.DisplayFields()[0]);
    }

    [Fact]
    public void Html_report_shows_case_fields()
    {
        var result = new AuditResult
        {
            StartedAtUtc = DateTimeOffset.Parse("2026-01-01T10:00:00Z"),
            FinishedAtUtc = DateTimeOffset.Parse("2026-01-01T10:05:00Z")
        };
        var meta = CaseMetadataReader.Parse("""{ "caseNumber": "ДЕЛО-77", "examiner": "Иванов" }""");

        var html = ForensicReportBuilder.BuildHtml(result, caseMetadata: meta);

        Assert.Contains("ДЕЛО-77", html, StringComparison.Ordinal);
        Assert.Contains("Иванов", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_report_without_case_is_unaffected()
    {
        var result = new AuditResult
        {
            StartedAtUtc = DateTimeOffset.Parse("2026-01-01T10:00:00Z"),
            FinishedAtUtc = DateTimeOffset.Parse("2026-01-01T10:05:00Z")
        };

        var html = ForensicReportBuilder.BuildHtml(result, caseMetadata: CaseMetadata.None);

        Assert.Contains("Компьютер:", html, StringComparison.Ordinal);
    }
}
