namespace UsbForensicAudit;

/// <summary>Вид алерта фонового мониторинга.</summary>
public enum MonitorAlertKind
{
    /// <summary>Подключено устройство, которого нет в доказательной базе.</summary>
    UnknownDevice,

    /// <summary>Подключено устройство, нарушающее политику «свой/чужой».</summary>
    PolicyViolation
}

/// <summary>Алерт фонового мониторинга — то, что уходит во все каналы доставки.</summary>
public sealed class MonitorAlert
{
    public required MonitorAlertKind Kind { get; init; }
    public required string Title { get; init; }
    public required string Details { get; init; }
    public required string DeviceKey { get; init; }
    public DateTimeOffset WhenUtc { get; init; } = DateTimeOffset.UtcNow;

    public string KindText => Kind == MonitorAlertKind.UnknownDevice
        ? "Неизвестное устройство"
        : "Нарушение политики";
}

/// <summary>
/// Правила алертов фонового мониторинга поверх живого снимка USB: неизвестные
/// устройства (через UnknownDeviceDetector) и нарушения политики «свой/чужой».
/// Чистая логика — детектор и политика приходят снаружи, WMI здесь нет.
/// </summary>
public static class LiveMonitorRules
{
    /// <summary>
    /// Представление живого устройства для решения политики: серийник у live-записи
    /// отдельным полем не приходит и извлекается из последнего сегмента DeviceId
    /// (USB\VID_xxxx&amp;PID_xxxx\СЕРИЙНИК); сегмент с «&amp;» — это сгенерированный
    /// Windows идентификатор, а не серийник, он политикой не сверяется.
    /// </summary>
    public static UsbDeviceRecord ToPolicyRecord(LiveUsbDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);

        return new UsbDeviceRecord
        {
            Vid = device.Vid,
            Pid = device.Pid,
            Serial = ExtractSerial(device.DeviceId),
            DeviceInstanceId = device.DeviceId,
            FriendlyName = device.DeviceName
        };
    }

    /// <summary>
    /// Алерты по свежему снимку: неизвестные устройства из детектора плюс
    /// нарушения политики среди всех подключённых. Повторные алерты по одному
    /// устройству отсекаются переданным набором уже поднятых ключей.
    /// </summary>
    public static IReadOnlyList<MonitorAlert> Evaluate(
        IReadOnlyList<LiveUsbDevice> snapshot,
        IReadOnlyList<LiveUsbDevice> unknownDevices,
        DevicePolicy policy,
        ISet<string> alreadyAlerted)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(unknownDevices);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(alreadyAlerted);

        var alerts = new List<MonitorAlert>();

        foreach (var device in unknownDevices)
        {
            var key = $"unknown|{DeviceKeyOf(device)}";
            if (!alreadyAlerted.Add(key))
            {
                continue;
            }

            alerts.Add(new MonitorAlert
            {
                Kind = MonitorAlertKind.UnknownDevice,
                Title = $"Неизвестное устройство: {device.DeviceName}",
                Details = $"{device.VidPidText}; {device.DeviceId}. В доказательной базе устройство не встречалось.",
                DeviceKey = DeviceKeyOf(device)
            });
        }

        if (!policy.IsEmpty)
        {
            foreach (var device in snapshot)
            {
                var decision = policy.Decide(ToPolicyRecord(device));
                if (decision is not (DevicePolicyDecision.Blocked or DevicePolicyDecision.Unlisted))
                {
                    continue;
                }

                var key = $"policy|{DeviceKeyOf(device)}";
                if (!alreadyAlerted.Add(key))
                {
                    continue;
                }

                var reason = decision == DevicePolicyDecision.Blocked
                    ? "устройство в чёрном списке"
                    : "устройства нет в списке разрешённых";
                alerts.Add(new MonitorAlert
                {
                    Kind = MonitorAlertKind.PolicyViolation,
                    Title = $"Нарушение политики: {device.DeviceName}",
                    Details = $"{device.VidPidText}; {device.DeviceId}. Решение политики: {reason}.",
                    DeviceKey = DeviceKeyOf(device)
                });
            }
        }

        return alerts;
    }

    private static string DeviceKeyOf(LiveUsbDevice device) =>
        string.IsNullOrWhiteSpace(device.StableKey) ? device.DeviceId : device.StableKey;

    private static string ExtractSerial(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return "";
        }

        var lastSlash = deviceId.LastIndexOf('\\');
        if (lastSlash < 0 || lastSlash == deviceId.Length - 1)
        {
            return "";
        }

        var tail = deviceId[(lastSlash + 1)..];
        return tail.Contains('&') ? "" : tail;
    }
}
