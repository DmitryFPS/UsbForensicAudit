namespace UsbForensicAudit;

/// <summary>Решение политики по конкретному устройству.</summary>
public enum DevicePolicyDecision
{
    /// <summary>Политика не задана — устройства не оценивались.</summary>
    NotEvaluated,

    /// <summary>Устройство в списке разрешённых.</summary>
    Approved,

    /// <summary>Устройство в чёрном списке — прямой запрет.</summary>
    Blocked,

    /// <summary>Включён режим строгого allowlist, а устройства в списке разрешённых нет.</summary>
    Unlisted
}

/// <summary>
/// Правило политики: совпадение по VID:PID и/или серийному номеру. Пустое поле
/// означает «любое значение», поэтому правило только по VID:PID покрывает все
/// экземпляры модели, а правило с серийником — конкретный носитель.
/// </summary>
public sealed class DevicePolicyRule
{
    public string? Vid { get; init; }
    public string? Pid { get; init; }
    public string? Serial { get; init; }

    /// <summary>Свободная пометка (кому выдано, инвентарный номер) — попадает в отчёт.</summary>
    public string? Note { get; init; }

    public bool Matches(UsbDeviceRecord device)
    {
        // Хотя бы одно поле правила должно быть задано, иначе правило совпало бы со всем.
        if (string.IsNullOrWhiteSpace(Vid) && string.IsNullOrWhiteSpace(Pid) && string.IsNullOrWhiteSpace(Serial))
        {
            return false;
        }

        return FieldMatches(Vid, device.Vid)
               && FieldMatches(Pid, device.Pid)
               && FieldMatches(Serial, device.Serial);
    }

    private static bool FieldMatches(string? ruleValue, string deviceValue) =>
        string.IsNullOrWhiteSpace(ruleValue)
        || string.Equals(ruleValue.Trim(), deviceValue?.Trim(), StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Политика допустимых устройств. Два списка: разрешённые и запрещённые.
/// В строгом режиме (<see cref="AllowlistEnforced"/>) любое устройство вне списка
/// разрешённых считается нарушением — модель «подключать можно только своё».
/// </summary>
public sealed class DevicePolicy
{
    public required IReadOnlyList<DevicePolicyRule> Allowed { get; init; }
    public required IReadOnlyList<DevicePolicyRule> Blocked { get; init; }
    public required bool AllowlistEnforced { get; init; }

    public bool IsEmpty => Allowed.Count == 0 && Blocked.Count == 0;

    public static DevicePolicy None { get; } = new()
    {
        Allowed = [],
        Blocked = [],
        AllowlistEnforced = false
    };

    /// <summary>Решение по устройству. Чёрный список приоритетнее белого.</summary>
    public DevicePolicyDecision Decide(UsbDeviceRecord device)
    {
        if (IsEmpty)
        {
            return DevicePolicyDecision.NotEvaluated;
        }

        if (Blocked.Any(rule => rule.Matches(device)))
        {
            return DevicePolicyDecision.Blocked;
        }

        if (Allowed.Any(rule => rule.Matches(device)))
        {
            return DevicePolicyDecision.Approved;
        }

        return AllowlistEnforced ? DevicePolicyDecision.Unlisted : DevicePolicyDecision.NotEvaluated;
    }
}
