namespace UsbForensicAudit;

public static class DateDisplay
{
    private static readonly DateTimeOffset MinimumReliableDateUtc = new(new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc));

    public static string FormatMoscow(DateTimeOffset? timestampUtc)
    {
        if (timestampUtc is null || !IsReliable(timestampUtc.Value))
        {
            return "нет точной даты";
        }

        var moscow = ToMoscow(timestampUtc.Value);
        return moscow.ToString(
            "dd.MM.yyyy HH:mm:ss",
            System.Globalization.CultureInfo.InvariantCulture) + " МСК";
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
            var moscowTimeZone = TimeZoneInfo.FindSystemTimeZoneById("Russian Standard Time");
            return TimeZoneInfo.ConvertTime(timestampUtc, moscowTimeZone);
        }
        catch
        {
            return timestampUtc.ToUniversalTime().ToOffset(TimeSpan.FromHours(3));
        }
    }
}
