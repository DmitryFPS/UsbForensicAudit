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

    /// <summary>
    /// Перенос подтверждён (файл виден и на диске, и на устройстве в близкое время),
    /// но направление — на устройство или с устройства — определить нельзя.
    /// Такие строки раньше вообще не показывались, хотя это самые уверенные
    /// совпадения: именно они отвечают на вопрос «копировали ли файл на флешку».
    /// </summary>
    public bool IsUndirected { get; init; }

    /// <summary>Подтверждён ли вынос журналом изменений NTFS, а не только совпадением имён.</summary>
    public bool IsConfirmed => !Confidence.Equals("Low", StringComparison.OrdinalIgnoreCase);

    public string WhenText => DateDisplay.FormatMoscowOr(WhenUtc, "Время неизвестно");
    public string ConfidenceText => DeviceActivityHistory.DescribeConfidence(Confidence);

    public string DirectionText => IsUndirected
        ? "Перенос подтверждён, направление не определено"
        : "С компьютера на устройство";
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

    /// <summary>
    /// Подтверждённые переносы с неопределённым направлением. Раньше они
    /// учитывались только числом и не показывались в таблице, хотя разница
    /// событий меньше 10 минут — самое сильное свидетельство переноса.
    /// </summary>
    public required IReadOnlyList<ExfiltrationItem> UndirectedFiles { get; init; }

    /// <summary>Читался ли журнал изменений NTFS — без него вынос подтвердить нечем.</summary>
    public required bool JournalAvailable { get; init; }

    /// <summary>Признаки переноса, где направление определить не удалось.</summary>
    public int UndirectedCount => UndirectedFiles.Count;

    public int OutboundCount => OutboundFiles.Count;
    public int ConfirmedCount => OutboundFiles.Count(x => x.IsConfirmed);
    public int DeviceCount => OutboundFiles.Select(x => x.DeviceId).Distinct(StringComparer.OrdinalIgnoreCase).Count();
    public bool HasFindings => OutboundCount > 0;

    /// <summary>Есть ли что показать в таблице переноса: вынос или подтверждённый перенос без направления.</summary>
    public bool HasAnyIndication => OutboundCount > 0 || UndirectedCount > 0;

    /// <summary>Все строки для таблиц: сначала вынос, затем переносы без направления.</summary>
    public IReadOnlyList<ExfiltrationItem> DisplayFiles =>
        OutboundFiles.Concat(UndirectedFiles).ToList();

    /// <summary>
    /// Одна фраза о выносе данных для всех отчётов. Формулировка осторожна:
    /// «признаки выноса», а не «данные украдены» — инструмент даёт доводы, а не приговор.
    /// Оговорка о переносах без направления присутствует в обеих ветках: раньше при
    /// наличии хотя бы одного выноса ненаправленные признаки исчезали из вердикта.
    /// </summary>
    public string Verdict()
    {
        var undirected = UndirectedCount > 0
            ? $" Ещё {UndirectedCount} перенос(ов) подтверждены по времени, но направление не определено — они показаны в таблице отдельно."
            : "";

        if (!HasFindings)
        {
            var tail = JournalAvailable
                ? ""
                : " Журнал изменений NTFS не читался, поэтому вынос подтвердить нечем — проверка опиралась только на артефакты проводника.";
            var noFindings = UndirectedCount > 0
                ? "Однозначных признаков выноса файлов на съёмные носители не обнаружено."
                : "Признаков выноса файлов на съёмные носители не обнаружено.";
            return noFindings + undirected + tail;
        }

        var confirmed = ConfirmedCount > 0
            ? $" Из них {ConfirmedCount} подтверждены журналом изменений NTFS."
            : " Все они основаны только на совпадении имён — требуется ручная проверка.";
        return $"Признаки выноса данных: {OutboundCount} файл(ов) на {DeviceCount} устройств(а)." + confirmed + undirected;
    }

    public static ExfiltrationSummary Empty { get; } = new()
    {
        OutboundFiles = [],
        UndirectedFiles = [],
        JournalAvailable = false
    };
}
