namespace UsbForensicAudit;

/// <summary>
/// Порт генерации отчётов (HTML/PDF) и открытия готовых файлов. Реализация (QuestPDF, файловая
/// система) живёт в инфраструктуре; представление зависит только от абстракции.
/// </summary>
public interface IReportService
{
    string CreateHtml(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null);

    string CreatePdf(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null);

    string CreateBriefPdf(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null);

    void OpenFile(string path);
}
