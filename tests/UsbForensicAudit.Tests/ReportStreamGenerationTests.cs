using System;
using System.IO;
using System.Text;
using ClosedXML.Excel;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Потоковые перегрузки генераторов отчётов: содержимое PDF и Excel проверяется
/// через MemoryStream, без записи на диск. До появления перегрузок генераторы
/// умели писать только в файл, и проверить результат в юнит-тесте было нельзя.
/// </summary>
public sealed class ReportStreamGenerationTests
{
    private static ForensicReportContext CreateContext()
    {
        var result = new AuditResult
        {
            StartedAtUtc = DateTimeOffset.Parse("2026-01-01T10:00:00Z"),
            FinishedAtUtc = DateTimeOffset.Parse("2026-01-01T10:05:00Z")
        };
        return ForensicReportContext.Create(result);
    }

    [Fact]
    public void Excel_full_report_writes_workbook_to_stream()
    {
        using var output = new MemoryStream();
        ExcelReportGenerator.GenerateFull(output, CreateContext());

        output.Position = 0;
        using var workbook = new XLWorkbook(output);
        Assert.True(workbook.TryGetWorksheet("Сводка", out _));
    }

    [Fact]
    public void Excel_brief_report_writes_workbook_to_stream()
    {
        using var output = new MemoryStream();
        ExcelReportGenerator.GenerateBrief(output, CreateContext());

        output.Position = 0;
        using var workbook = new XLWorkbook(output);
        Assert.True(workbook.TryGetWorksheet("Сводка", out _));
    }

    [Fact]
    public void Analyst_note_excel_writes_workbook_to_stream()
    {
        using var output = new MemoryStream();
        AnalystNoteExcelReport.Generate(output, CreateContext());

        output.Position = 0;
        using var workbook = new XLWorkbook(output);
        Assert.True(workbook.TryGetWorksheet("Устройства", out _));
    }

    [Fact]
    public void Forensic_pdf_report_writes_pdf_to_stream()
    {
        PdfFontHelper.EnsureRegistered();
        using var output = new MemoryStream();

        ForensicPdfReport.Generate(output, CreateContext());

        AssertLooksLikePdf(output);
    }

    [Fact]
    public void Executive_brief_pdf_writes_pdf_to_stream()
    {
        PdfFontHelper.EnsureRegistered();
        using var output = new MemoryStream();

        ExecutiveBriefPdfReport.Generate(output, CreateContext());

        AssertLooksLikePdf(output);
    }

    [Fact]
    public void Analyst_note_pdf_writes_pdf_to_stream()
    {
        PdfFontHelper.EnsureRegistered();
        using var output = new MemoryStream();

        AnalystNotePdfReport.Generate(output, CreateContext());

        AssertLooksLikePdf(output);
    }

    private static void AssertLooksLikePdf(MemoryStream stream)
    {
        var bytes = stream.ToArray();
        Assert.True(bytes.Length > 1000, "PDF подозрительно мал — генерация не удалась.");
        Assert.Equal("%PDF", Encoding.ASCII.GetString(bytes, 0, 4));
    }
}
