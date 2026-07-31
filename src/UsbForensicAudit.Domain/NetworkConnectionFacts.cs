using System.Text;

namespace UsbForensicAudit;

/// <summary>
/// Всё, что известно об одной связи, одним связным текстом.
///
/// Нужен и окну подробностей, и отчётам: пока каждый писал этот перечень
/// по-своему, в окне и в отчёте о той же связи стояли разные слова, и сверить их
/// было нельзя. Каждая дата идёт вместе с указанием, откуда она взята: дата без
/// источника в проверке ничего не стоит.
/// </summary>
public static class NetworkConnectionFacts
{
    public static IReadOnlyList<(string Name, string Value)> Rows(NetworkConnectionRecord record)
    {
        var rows = new List<(string, string)>
        {
            ("Как связывались", record.KindText),
            ("С чем именно", record.TargetText),
            ("Кто начал соединение", record.DirectionText),
            ("Первое подключение", WithProvenance(record.FirstSeenText, record.FirstSeenProvenance)),
            ("Последнее подключение", WithProvenance(record.LastSeenText, record.LastSeenProvenance)),
            ("Чем защищено", record.SecurityText),
            ("Через что шла связь", record.AdapterText),
            ("Адреса этой машины", record.LocalAddressesText),
            ("Учётная запись", Or(record.AccountText, "Учётной записи в записях нет")),
            ("Что нашлось внутри", record.ActivityText),
            ("Простыми словами", Or(record.DetailsText, "Пояснения к этой связи нет")),
            ("Откуда взято", record.SourcesText),
            ("Ссылка на источник", Or(record.Provenance, "Ссылки на источник нет"))
        };

        return rows;
    }

    public static string Describe(NetworkConnectionRecord record)
    {
        var builder = new StringBuilder();
        foreach (var (name, value) in Rows(record))
        {
            builder.AppendLine($"{name}: {value}");
        }

        return builder.ToString().TrimEnd();
    }

    /// <summary>
    /// Дата вместе с тем, что она означает. «Первое подключение: 27.07.2026» без
    /// пояснения читается как точный факт, хотя у одной связи это запись реестра,
    /// а у другой — самое раннее из найденных обращений.
    /// </summary>
    private static string WithProvenance(string date, string provenance)
    {
        var text = ReportText.ForDisplayOrClean(provenance, 400);
        return text.Length > 0 ? $"{date} ({text})" : date;
    }

    private static string Or(string value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;
}
