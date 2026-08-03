namespace UsbForensicAudit;

/// <summary>
/// Единая шкала серьёзности находок. Раньше HTML-отчёт, Excel-отчёт и UI держали
/// по собственной копии ранжирования с несовместимыми значениями (HIGH=3 против HIGH=4),
/// из-за чего одинаковые находки сортировались по-разному в разных форматах.
/// </summary>
public static class ReportSeverity
{
    /// <summary>
    /// Ранг серьёзности для сортировки: чем выше значение, тем серьёзнее находка.
    /// Неизвестные и пустые значения получают ранг 0 и уходят в конец списка.
    /// </summary>
    public static int Rank(string? severity) => severity?.ToLowerInvariant() switch
    {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0
    };
}
