namespace UsbForensicAudit;

/// <summary>Ограничения поиска должны быть видны вместе с выводами, а не только в приложении к отчёту.</summary>
public sealed record ScanCoverageSummary(bool HasLimitations, string Summary, IReadOnlyList<string> Details)
{
    public static ScanCoverageSummary From(AuditResult result)
    {
        var incomplete = result.Coverage.Sources
            .Where(x => x.Status is "Error" or "Partial" or "NotRun" || x.Capped).ToArray();
        var details = incomplete.Select(x => $"{x.Source}: {x.Status}; записей: {x.Count}. {x.Error}")
            .Concat(result.SourceWarnings.Where(x => !IsInformational(x, result)))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return details.Length == 0
            ? new(false, "Сканирование завершено.", details)
            : new(true, "Проверка выполнена с ограничениями. Часть источников недоступна или прочитана не полностью; "
                        + "отсутствие находок не исключает подключения и действия с файлами.", details);
    }

    // В старых сессиях эти пояснения сохранялись рядом с ошибками источников.
    private static bool IsInformational(string message, AuditResult result) =>
        (result.Privileges.CanReadProtectedRegistry && message == result.Privileges.Describe())
        || message.StartsWith("Записей, доставшихся от эталонного образа:", StringComparison.Ordinal)
        || message.StartsWith("Записей со штампом раньше установки Windows:", StringComparison.Ordinal);
}
