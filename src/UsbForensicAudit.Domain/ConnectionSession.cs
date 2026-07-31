namespace UsbForensicAudit;

/// <summary>
/// Один сеанс работы устройства: от подключения до отключения. Отчёт по первой
/// и последней дате не отвечает на вопрос, сколько раз устройство подключали и
/// как долго оно оставалось в машине, — а именно это обычно и выясняется.
/// </summary>
public sealed class ConnectionSession
{
    public DateTimeOffset StartUtc { get; set; }
    public DateTimeOffset? EndUtc { get; set; }
    public string StartProvenance { get; set; } = "";
    public string EndProvenance { get; set; } = "";

    /// <summary>
    /// Сеанс не закрыт: события отключения нет. Устройство либо подключено до
    /// сих пор, либо журнал события не сохранил.
    /// </summary>
    public bool IsOpen => !EndUtc.HasValue;

    public TimeSpan? Duration => EndUtc.HasValue ? EndUtc.Value - StartUtc : null;

    public string DurationText
    {
        get
        {
            if (Duration is not { } duration)
            {
                return "не закрыт";
            }

            if (duration < TimeSpan.Zero)
            {
                return "неизвестно";
            }

            if (duration.TotalMinutes < 1)
            {
                return $"{(int)duration.TotalSeconds} с";
            }

            return duration.TotalHours < 1
                ? $"{(int)duration.TotalMinutes} мин"
                : $"{(int)duration.TotalHours} ч {duration.Minutes} мин";
        }
    }
}
