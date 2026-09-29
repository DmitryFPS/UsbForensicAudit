namespace UsbForensicAudit;

/// <summary>Ограничения поиска должны быть видны вместе с выводами, а не только в приложении к отчёту.</summary>
public sealed record ScanCoverageSummary(bool HasLimitations, string Summary, IReadOnlyList<string> Details)
{
    public static ScanCoverageSummary From(AuditResult result)
    {
        var incomplete = result.Coverage.Sources
            .Where(x => x.Status is "Error" or "Partial" || x.Capped).ToArray();
        var details = incomplete.Select(x => $"{x.Source}: {x.Status}; записей: {x.Count}. {x.Error}")
            .Concat(result.SourceWarnings).Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return details.Length == 0
            ? new(false, "Сканирование завершено.", details)
            : new(true, "Проверка выполнена с ограничениями. Часть источников недоступна или прочитана не полностью; "
                        + "отсутствие находок не исключает подключения и действия с файлами.", details);
    }
}
