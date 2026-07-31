namespace UsbForensicAudit;

/// <summary>
/// Состояние канала журнала Windows. Пустой результат по каналу означает разное:
/// событий не было, канал выключен, или журнал перезаписан по кругу. Без этого
/// различия отсутствие события нельзя толковать как отсутствие подключения.
/// </summary>
public sealed class EventChannelState
{
    public string Channel { get; set; } = "";
    public bool Exists { get; set; }
    public bool IsEnabled { get; set; }
    public long MaximumSizeBytes { get; set; }
    public long FileSizeBytes { get; set; }
    public long RecordCount { get; set; }

    /// <summary>
    /// Время самой ранней сохранившейся записи. Всё, что было до него, из канала
    /// уже вытеснено, и события подключения там искать бесполезно.
    /// </summary>
    public DateTimeOffset? OldestRecordUtc { get; set; }

    public string Error { get; set; } = "";

    /// <summary>
    /// Канал переполнен и пишется по кругу: старые записи вытесняются новыми.
    /// </summary>
    public bool IsLikelyWrapped =>
        MaximumSizeBytes > 0 && FileSizeBytes >= MaximumSizeBytes * 0.95;

    /// <summary>
    /// По каналу можно судить об отсутствии события только если он существует,
    /// включён и охватывает нужный момент времени.
    /// </summary>
    public bool AbsenceIsMeaningful(DateTimeOffset momentUtc) =>
        Exists && IsEnabled && string.IsNullOrEmpty(Error)
        && (!OldestRecordUtc.HasValue || OldestRecordUtc.Value <= momentUtc);

    public string Describe()
    {
        if (!Exists)
        {
            return $"Канал {Channel} в этой системе отсутствует. Отсутствие событий в нём ничего не доказывает.";
        }

        if (!string.IsNullOrEmpty(Error))
        {
            return $"Канал {Channel} прочитать не удалось: {Error}. Отсутствие событий в нём ничего не доказывает.";
        }

        if (!IsEnabled)
        {
            return $"Канал {Channel} выключен. События в него не записывались, "
                   + "поэтому их отсутствие не означает, что устройство не подключали.";
        }

        var coverage = OldestRecordUtc.HasValue
            ? $" Самая ранняя сохранившаяся запись: {DateDisplay.FormatMoscowOr(OldestRecordUtc, "неизвестно")}."
            : "";

        var wrapped = IsLikelyWrapped
            ? " Журнал заполнен и пишется по кругу: более старые события уже вытеснены."
            : "";

        return $"Канал {Channel} включён, записей: {RecordCount}.{coverage}{wrapped}";
    }
}
