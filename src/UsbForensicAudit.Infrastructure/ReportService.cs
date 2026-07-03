using System.Diagnostics;
using System.IO;

namespace UsbForensicAudit;

public sealed class ReportService
{
    public string CreateHtml(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"UsbForensicAudit_{DateTime.Now:yyyyMMdd_HHmmss}.html");
        File.WriteAllText(path, ForensicReportBuilder.BuildHtml(result, externalUtilitySnapshot), System.Text.Encoding.UTF8);
        return path;
    }

    public string CreatePdf(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"UsbForensicAudit_{DateTime.Now:yyyyMMdd_HHmmss}.pdf");
        PdfFontHelper.EnsureRegistered();
        ForensicPdfReport.Generate(path, ForensicReportContext.Create(result, externalUtilitySnapshot));
        return path;
    }

    public string CreateBriefPdf(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"UsbForensicAudit_Svodnyj_{DateTime.Now:yyyyMMdd_HHmmss}.pdf");
        PdfFontHelper.EnsureRegistered();
        ExecutiveBriefPdfReport.Generate(path, ForensicReportContext.Create(result, externalUtilitySnapshot));
        return path;
    }

    public void OpenFile(string path)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = path,
            UseShellExecute = true
        });
    }
}
