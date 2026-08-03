namespace UsbForensicAudit;

/// <summary>
/// Порт генерации отчётов (HTML/PDF/Excel) и открытия готовых файлов. Реализация (QuestPDF, ClosedXML, файловая
/// система) живёт в инфраструктуре; представление зависит только от абстракции.
/// </summary>
public interface IReportService
{
    public string CreateHtml(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null);

    public string CreatePdf(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null);

    public string CreateBriefPdf(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null);

    /// <summary>
    /// Аналитическая записка: сжатый рассказ с общей хронологией — устройства,
    /// сеть, действия пользователя и очистка одной лентой времени.
    /// </summary>
    public string CreateAnalystNotePdf(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null);

    /// <summary>Та же аналитическая записка, но в Excel — по листу на раздел.</summary>
    public string CreateAnalystNoteExcel(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null);

    public string CreateExcel(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null);

    public string CreateBriefExcel(AuditResult result, string directory, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null);

    /// <summary>Единый таймлайн доказательств в CSV (UTF-8 с BOM) для Timeline Explorer/Excel.</summary>
    public string CreateTimelineCsv(AuditResult result, string directory);

    public void OpenFile(string path);
}
