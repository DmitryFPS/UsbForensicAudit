namespace UsbForensicAudit;

/// <summary>
/// Единая точка отображения дат. Раньше зона была жёстко зашита: «Russian
/// Standard Time» с fallback на UTC+3 — на машине в другом часовом поясе все
/// даты отчёта врали относительно настенных часов аналитика. Теперь зона
/// отображения настраивается: приложения при старте передают зону машины,
/// а подпись («МСК» или «UTC+HH:mm») вычисляется из фактической зоны.
/// По умолчанию остаётся московская зона — так сохраняется поведение уже
/// сохранённых сессий и голых вызовов без инициализации.
/// </summary>
public static class DateDisplay
{
    private static readonly DateTimeOffset MinimumReliableDateUtc = new(new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc));

    private static TimeZoneInfo _displayZone = FindMoscowZone();

    /// <summary>
    /// Зона, в которой показываются все даты. Приложение устанавливает её при
    /// старте (обычно <see cref="TimeZoneInfo.Local"/>); тесты могут задать
    /// фиксированную зону для детерминизма.
    /// </summary>
    public static TimeZoneInfo DisplayZone
    {
        get => _displayZone;
        set => _displayZone = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>Короткая подпись зоны рядом с датой: «МСК» или «UTC+05:00».</summary>
    public static string ZoneLabel => IsMoscowLike(_displayZone) ? "МСК" : FormatOffsetLabel(_displayZone);

    /// <summary>Подпись зоны для шапок отчётов: «московском времени (МСК)» и т.п.</summary>
    public static string ZoneDescription => IsMoscowLike(_displayZone)
        ? "московском времени (МСК)"
        : $"часовом поясе {FormatOffsetLabel(_displayZone)} ({_displayZone.Id})";

    public static string FormatMoscow(DateTimeOffset? timestampUtc)
    {
        if (timestampUtc is null || !IsReliable(timestampUtc.Value))
        {
            return "нет точной даты";
        }

        var display = ToMoscow(timestampUtc.Value);
        return display.ToString(
            "dd.MM.yyyy HH:mm:ss",
            System.Globalization.CultureInfo.InvariantCulture) + " " + ZoneLabel;
    }

    public static string FormatMoscowOr(DateTimeOffset? timestampUtc, string fallback)
    {
        if (timestampUtc is null || !IsReliable(timestampUtc.Value))
        {
            return fallback;
        }

        return FormatMoscow(timestampUtc);
    }

    public static bool IsReliable(DateTimeOffset timestampUtc)
    {
        return timestampUtc >= MinimumReliableDateUtc && timestampUtc <= DateTimeOffset.UtcNow.AddDays(2);
    }

    public static DateTimeOffset ToMoscow(DateTimeOffset timestampUtc)
    {
        try
        {
            return TimeZoneInfo.ConvertTime(timestampUtc, _displayZone);
        }
        catch
        {
            return timestampUtc.ToUniversalTime().ToOffset(TimeSpan.FromHours(3));
        }
    }

    private static TimeZoneInfo FindMoscowZone()
    {
        foreach (var id in new[] { "Russian Standard Time", "Europe/Moscow" })
        {
            try
            {
                return TimeZoneInfo.FindSystemTimeZoneById(id);
            }
            catch (TimeZoneNotFoundException)
            {
            }
            catch (InvalidTimeZoneException)
            {
            }
        }

        return TimeZoneInfo.CreateCustomTimeZone("UFA Moscow", TimeSpan.FromHours(3), "Москва (UTC+3)", "МСК");
    }

    private static bool IsMoscowLike(TimeZoneInfo zone) =>
        zone.BaseUtcOffset == TimeSpan.FromHours(3)
        && (zone.Id.Contains("Moscow", StringComparison.OrdinalIgnoreCase)
            || zone.Id.Contains("Russian", StringComparison.OrdinalIgnoreCase)
            || zone.Id.Equals("UFA Moscow", StringComparison.OrdinalIgnoreCase));

    private static string FormatOffsetLabel(TimeZoneInfo zone)
    {
        var offset = zone.GetUtcOffset(DateTimeOffset.UtcNow);
        var sign = offset < TimeSpan.Zero ? "-" : "+";
        return $"UTC{sign}{Math.Abs(offset.Hours):00}:{Math.Abs(offset.Minutes):00}";
    }
}
