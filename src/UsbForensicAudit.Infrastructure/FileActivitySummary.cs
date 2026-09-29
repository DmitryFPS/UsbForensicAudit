namespace UsbForensicAudit;

/// <summary>Считает исходные следы один раз и не превращает предположение о носителе в факт.</summary>
internal sealed record FileActivitySummary(int DirectCount, int UncertainCount, int DeviceCount)
{
    public int TruncatedDeviceCount { get; init; }
    public string Verdict => DirectCount > 0
        ? $"Найдены следы файловой активности: {DirectCount}; устройств с надёжной привязкой: {DeviceCount}"
        : UncertainCount > 0
            ? $"Возможная файловая активность: {UncertainCount} след(ов); устройство не установлено надёжно"
            : TruncatedDeviceCount > 0
                ? "Файловая активность не установлена: история ограничена"
                : "Следов работы с файлами не найдено";

    public string Explanation => (UncertainCount > 0
        ? $"Следов с неоднозначной или косвенной привязкой: {UncertainCount}. Они не подтверждают действия на каждом из возможных устройств. "
        : "") + (DirectCount > 0
        ? "Количество отражает найденные артефакты, а не точное число действий пользователя. "
        : "") + (TruncatedDeviceCount > 0
        ? $"История ограничена у {TruncatedDeviceCount} устройств; подсчёт относится только к показанной части. "
        : "");

    public static FileActivitySummary From(IEnumerable<(UsbDeviceRecord Device, DeviceActivityHistory History)> histories)
    {
        var direct = 0;
        var uncertain = 0;
        var devices = new HashSet<UsbDeviceRecord>();
        var all = histories.ToArray();
        var observations = all.SelectMany(h => h.History.Entries.Select(e => (h.Device, Entry: e)))
            .GroupBy(x => (x.Entry.TimestampUtc, x.Entry.Kind,
                Path: x.Entry.Path.ToUpperInvariant(), User: x.Entry.UserSid.ToUpperInvariant(),
                Source: x.Entry.Source.ToUpperInvariant(), x.Entry.Provenance));
        foreach (var observation in observations)
        {
            var strong = observation.Where(x => x.Entry.LinkConfidence.Equals("High", StringComparison.OrdinalIgnoreCase))
                .Select(x => x.Device).Distinct().ToArray();
            if (strong.Length == 1)
            {
                direct++;
                devices.Add(strong[0]);
            }
            else
            {
                uncertain++;
            }
        }
        return new(direct, uncertain, devices.Count)
        { TruncatedDeviceCount = all.Count(x => x.History.OmittedEntryCount > 0) };
    }
}
