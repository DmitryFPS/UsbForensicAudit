namespace UsbForensicAudit;

/// <summary>
/// Извлекает время создания из UUID версии 1. Идентификатор диска GPT обычно
/// именно такой: в нём записан момент разметки носителя с точностью до 100 нс.
/// Это независимая отметка времени — она лежит на самом носителе и не меняется
/// при чистке журналов Windows и веток реестра.
/// </summary>
public static class Uuid1Timestamp
{
    /// <summary>
    /// Отсчёт ведётся от перехода на григорианский календарь.
    /// </summary>
    private static readonly DateTimeOffset GregorianEpoch =
        new(1582, 10, 15, 0, 0, 0, TimeSpan.Zero);

    private static readonly DateTimeOffset EarliestPlausible = new(1990, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static bool TryDecode(string? value, out DateTimeOffset createdUtc)
    {
        createdUtc = default;
        return Guid.TryParse((value ?? "").Trim().Trim('{', '}'), out var parsed)
               && TryDecode(parsed, out createdUtc);
    }

    public static bool TryDecode(Guid value, out DateTimeOffset createdUtc)
    {
        createdUtc = default;

        // Порядок байтов в Guid для первых трёх полей — как у платформы,
        // поэтому берём канонический вид, а не Guid.ToByteArray.
        var text = value.ToString("D");
        var parts = text.Split('-');
        if (parts.Length != 5)
        {
            return false;
        }

        if (parts[2][0] != '1')
        {
            return false;
        }

        var timeLow = Convert.ToUInt64(parts[0], 16);
        var timeMid = Convert.ToUInt64(parts[1], 16);
        var timeHigh = Convert.ToUInt64(parts[2], 16) & 0x0FFF;
        var ticks = (long)((timeHigh << 48) | (timeMid << 32) | timeLow);
        if (ticks <= 0)
        {
            return false;
        }

        try
        {
            var candidate = GregorianEpoch.AddTicks(ticks);
            if (candidate < EarliestPlausible || candidate > DateTimeOffset.UtcNow.AddDays(1))
            {
                return false;
            }

            createdUtc = candidate;
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }
}
