using System.Diagnostics;
using System.IO;

namespace UsbForensicAudit;

public sealed class ReportService : IReportService
{
    public string CreateHtml(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null)
    {
        return CreateAtomically(
            directory,
            $"UsbForensicAudit_{ReportTimestamp()}.html",
            path => File.WriteAllText(
                path,
                ForensicReportBuilder.BuildHtml(result, externalUtilitySnapshot),
                System.Text.Encoding.UTF8));
    }

    public string CreatePdf(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null)
    {
        return CreateAtomically(directory, $"UsbForensicAudit_{ReportTimestamp()}.pdf", path =>
        {
            PdfFontHelper.EnsureRegistered();
            ForensicPdfReport.Generate(path, ForensicReportContext.Create(result, externalUtilitySnapshot));
        });
    }

    public string CreateBriefPdf(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null)
    {
        return CreateAtomically(directory, $"UsbForensicAudit_Svodnyj_{ReportTimestamp()}.pdf", path =>
        {
            PdfFontHelper.EnsureRegistered();
            ExecutiveBriefPdfReport.Generate(path, ForensicReportContext.Create(result, externalUtilitySnapshot));
        });
    }

    public string CreateExcel(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null)
    {
        return CreateAtomically(
            directory,
            $"UsbForensicAudit_{ReportTimestamp()}.xlsx",
            path => ExcelReportGenerator.GenerateFull(path, ForensicReportContext.Create(result, externalUtilitySnapshot)));
    }

    public string CreateBriefExcel(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null)
    {
        return CreateAtomically(
            directory,
            $"UsbForensicAudit_Svodnyj_{ReportTimestamp()}.xlsx",
            path => ExcelReportGenerator.GenerateBrief(path, ForensicReportContext.Create(result, externalUtilitySnapshot)));
    }

    public void OpenFile(string path)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = path,
            UseShellExecute = true
        });
    }

    private static string ReportTimestamp() =>
        DateDisplay.ToMoscow(DateTimeOffset.UtcNow).ToString("yyyyMMdd_HHmmss_fff");

    private static string CreateAtomically(string directory, string fileName, Action<string> generate)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, fileName);
        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileNameWithoutExtension(fileName)}.{Guid.NewGuid():N}.tmp{Path.GetExtension(fileName)}");
        try
        {
            generate(temporaryPath);
            File.Move(temporaryPath, path, overwrite: false);
            return path;
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
