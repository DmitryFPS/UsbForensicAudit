namespace UsbForensicAudit;

/// <summary>Итог оценки одного устройства политикой.</summary>
public sealed class DevicePolicyResultItem
{
    public required string DeviceDisplayName { get; init; }
    public required string VidPidText { get; init; }
    public required string SerialText { get; init; }
    public required DevicePolicyDecision Decision { get; init; }

    /// <summary>Является ли решение нарушением политики (чёрный список или вне allowlist).</summary>
    public bool IsViolation => Decision is DevicePolicyDecision.Blocked or DevicePolicyDecision.Unlisted;

    public string DecisionText => Decision switch
    {
        DevicePolicyDecision.Approved => "Разрешено политикой",
        DevicePolicyDecision.Blocked => "Запрещено (чёрный список)",
        DevicePolicyDecision.Unlisted => "Нарушение: устройства нет в списке разрешённых",
        _ => "Политикой не оценивается"
    };
}

/// <summary>
/// Сводка соответствия политике по всем устройствам. Отвечает на корпоративный
/// вопрос «подключали ли не разрешённое устройство» отдельным вердиктом.
/// </summary>
public sealed class DevicePolicySummary
{
    public required IReadOnlyList<DevicePolicyResultItem> Items { get; init; }
    public required bool PolicyDefined { get; init; }

    public IReadOnlyList<DevicePolicyResultItem> Violations =>
        Items.Where(x => x.IsViolation).ToArray();

    public int BlockedCount => Items.Count(x => x.Decision == DevicePolicyDecision.Blocked);
    public int UnlistedCount => Items.Count(x => x.Decision == DevicePolicyDecision.Unlisted);
    public int ApprovedCount => Items.Count(x => x.Decision == DevicePolicyDecision.Approved);
    public bool HasViolations => Violations.Count > 0;

    public string Verdict()
    {
        if (!PolicyDefined)
        {
            return "Политика допустимых устройств не задана — проверка соответствия не выполнялась. "
                   + "Задайте списки в device-policy.json рядом с программой, чтобы включить контроль.";
        }

        if (!HasViolations)
        {
            return $"Нарушений политики устройств не обнаружено (разрешённых подключений: {ApprovedCount}).";
        }

        return $"Нарушения политики устройств: {Violations.Count}"
               + (BlockedCount > 0 ? $", из них из чёрного списка: {BlockedCount}" : "")
               + (UnlistedCount > 0 ? $", вне списка разрешённых: {UnlistedCount}" : "")
               + ". Эти подключения требуют объяснения.";
    }

    public static DevicePolicySummary NotDefined { get; } = new()
    {
        Items = [],
        PolicyDefined = false
    };
}
