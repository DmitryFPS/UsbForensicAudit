namespace UsbForensicAudit;

/// <summary>
/// Одна строка перечня выноса данных: какой файл, на какое устройство, когда и
/// насколько уверенно. Собирается из признаков переноса (<see cref="CopyIndication"/>),
/// у которых направление — «с компьютера на устройство».
/// </summary>
public sealed class ExfiltrationItem
{
    public required string FileName { get; init; }
    public required string DeviceDisplayName { get; init; }
    public required string DeviceId { get; init; }
    public DateTimeOffset? WhenUtc { get; init; }
    public required string Confidence { get; init; }
    public required string Basis { get; init; }

    /// <summary>Подтверждён ли вынос журналом изменений NTFS, а не только совпадением имён.</summary>
    public bool IsConfirmed => !Confidence.Equals("Low", StringComparison.OrdinalIgnoreCase);

    public string WhenText => DateDisplay.FormatMoscowOr(WhenUtc, "Время неизвестно");
    public string ConfidenceText => DeviceActivityHistory.DescribeConfidence(Confidence);
}

/// <summary>
/// Сводка «ушли ли данные наружу» — прямой ответ на главный вопрос расследования
/// утечки. Отделяет подтверждённый вынос на съёмный носитель (направление
/// «на устройство») от переноса с неопределённым направлением, чтобы вывод
/// «данные вынесли» не смешивался с «работали с файлом того же имени».
/// </summary>
public sealed class ExfiltrationSummary
{
    public required IReadOnlyList<ExfiltrationItem> OutboundFiles { get; init; }

    /// <summary>Признаки переноса, где направление определить не удалось (для оговорки в выводе).</summary>
    public required int UndirectedCount { get; init; }

    /// <summary>Читался ли журнал изменений NTFS — без него вынос подтвердить нечем.</summary>
    public required bool JournalAvailable { get; init; }

    public int OutboundCount => OutboundFiles.Count;
    public int ConfirmedCount => OutboundFiles.Count(x => x.IsConfirmed);
    public int DeviceCount => OutboundFiles.Select(x => x.DeviceId).Distinct(StringComparer.OrdinalIgnoreCase).Count();
    public bool HasFindings => OutboundCount > 0;

    /// <summary>
    /// Одна фраза о выносе данных для всех отчётов. Формулировка осторожна:
    /// «признаки выноса», а не «данные украдены» — инструмент даёт доводы, а не приговор.
    /// </summary>
    public string Verdict()
    {
        if (!HasFindings)
        {
            var tail = JournalAvailable
                ? ""
                : " Журнал изменений NTFS не читался, поэтому вынос подтвердить нечем — проверка опиралась только на артефакты проводника.";
            var undirected = UndirectedCount > 0
                ? $" Есть {UndirectedCount} признак(ов) переноса без определённого направления — их стоит просмотреть вручную."
                : "";
            return "Признаков выноса файлов на съёмные носители не обнаружено." + undirected + tail;
        }

        var confirmed = ConfirmedCount > 0
            ? $" Из них {ConfirmedCount} подтверждены журналом изменений NTFS."
            : " Все они основаны только на совпадении имён — требуется ручная проверка.";
        return $"Признаки выноса данных: {OutboundCount} файл(ов) на {DeviceCount} устройств(а)." + confirmed;
    }

    public static ExfiltrationSummary Empty { get; } = new()
    {
        OutboundFiles = [],
        UndirectedCount = 0,
        JournalAvailable = false
    };
}
