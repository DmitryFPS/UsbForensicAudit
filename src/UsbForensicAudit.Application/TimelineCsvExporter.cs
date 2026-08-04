using System.Globalization;
using System.Text;

namespace UsbForensicAudit;

/// <summary>
/// Строит единый таймлайн доказательств в формате CSV (RFC 4180) для внешних
/// инструментов аналитика — Timeline Explorer, Excel, супертаймлайн. Каждая
/// строка — одно событие; время дано и в UTC (сортировка/сопоставление между
/// машинами), и в зоне отображения (чтение человеком). Возвращает строку:
/// запись на диск и кодировку выбирает вызывающий слой.
/// </summary>
public static class TimelineCsvExporter
{
    // Заголовок второй колонки строится по фактической зоне отображения:
    // раньше подпись «МСК» была жёсткой и врала на машинах в другом поясе.
    private static string[] Headers =>
    [
        "Время (UTC)", $"Время ({DateDisplay.ZoneLabel})", "Источник", "Провайдер", "Канал",
        "Событие", "Категория", "Сила", "Уверенность", "Устройство", "Описание"
    ];

    public static string BuildTimelineCsv(AuditResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var builder = new StringBuilder();
        builder.Append(string.Join(',', Headers.Select(Escape))).Append("\r\n");

        foreach (var evidence in result.Evidence.OrderBy(x => x.TimestampUtc))
        {
            var cells = new[]
            {
                evidence.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                DateDisplay.FormatMoscow(evidence.TimestampUtc),
                evidence.Source,
                evidence.Provider,
                evidence.Channel,
                evidence.EventId,
                evidence.EvidenceCategory,
                evidence.EvidenceStrength,
                evidence.Confidence,
                evidence.DeviceHint,
                evidence.Summary
            };
            builder.Append(string.Join(',', cells.Select(Escape))).Append("\r\n");
        }

        return builder.ToString();
    }

    /// <summary>
    /// Экранирование по RFC 4180: поле берётся в кавычки, если содержит запятую,
    /// кавычку или перевод строки; внутренние кавычки удваиваются. Переводы строк
    /// внутри значения заменяются пробелом, чтобы одна запись оставалась одной
    /// строкой файла (Timeline Explorer и Excel так надёжнее её читают).
    /// </summary>
    private static string Escape(string? value)
    {
        var text = (value ?? string.Empty).Replace("\r\n", " ").Replace('\r', ' ').Replace('\n', ' ');
        if (text.Contains(',') || text.Contains('"'))
        {
            return "\"" + text.Replace("\"", "\"\"") + "\"";
        }

        return text;
    }
}
