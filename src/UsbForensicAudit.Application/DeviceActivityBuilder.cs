using System.Text.RegularExpressions;

namespace UsbForensicAudit;

/// <summary>
/// Собирает историю работы на конкретном устройстве: какие папки открывали,
/// какие файлы открывали и удаляли, какие программы запускали.
///
/// Главная сложность не в том, чтобы найти следы, а в том, чтобы отнести их к
/// нужному устройству. Проводник запоминает путь «E:\Фото», а не серийный номер
/// носителя, и буква E за год могла достаться трём разным флешкам. Поэтому у
/// каждой записи хранится основание привязки и его надёжность, а буква диска,
/// побывавшая у нескольких устройств, честно понижается до предположения.
/// </summary>
public static partial class DeviceActivityBuilder
{
    /// <summary>
    /// Сколько записей показывать. Ограничение защищает окно и отчёт от
    /// многотысячных списков; о срезе сообщается читателю.
    /// </summary>
    public const int MaxEntries = 2000;

    public static DeviceActivityHistory Build(UsbDeviceRecord device, AuditResult result) =>
        Build(device, result.Devices, result.Evidence, result.FileChangeJournals);

    public static DeviceActivityHistory Build(
        UsbDeviceRecord device,
        IReadOnlyCollection<UsbDeviceRecord> allDevices,
        IReadOnlyCollection<EvidenceRecord> evidence,
        IReadOnlyCollection<FileChangeJournalState>? journals = null)
    {
        var keys = DeviceLinkKeys.Build(device, allDevices);
        var history = new DeviceActivityHistory
        {
            DeviceDisplayName = device.DisplayName,
            CanonicalDeviceId = device.CanonicalDeviceId,
            LinkKeys = keys.Describe(),
            CanSearchFileActivity = keys.HasFileActivityKey,
            JournalCoverage = (journals ?? [])
                .Select(x => x.CoverageText)
                .Where(x => x.Length > 0)
                .ToList()
        };

        if (!keys.HasAnyKey)
        {
            return history;
        }

        var entries = new List<DeviceActivityEntry>();
        foreach (var record in evidence)
        {
            if (IsDerivedSummary(record))
            {
                continue;
            }

            var link = keys.Match(record);
            if (link is null)
            {
                continue;
            }

            var kind = ClassifyKind(record);
            if (kind == DeviceActivityKind.Unknown)
            {
                continue;
            }

            entries.Add(new DeviceActivityEntry
            {
                TimestampUtc = record.TimestampUtc,
                Kind = kind,
                Path = ChoosePath(record),
                UserSid = record.UserSid,
                ResolvedUserName = record.ResolvedUserName,
                Source = record.Source,
                LinkBasis = link.Basis,
                LinkConfidence = link.Confidence,
                TimeMeaning = DescribeTimeMeaning(record),
                Provenance = record.Provenance.Length > 0 ? record.Provenance : record.SourceRecord
            });
        }

        history.Entries = Deduplicate(entries)
            .OrderByDescending(x => x.TimestampUtc)
            .Take(MaxEntries)
            .ToList();
        history.CopyIndications = MergeCopyIndications(device, history.Entries, keys, evidence);
        return history;
    }

    /// <summary>
    /// Признаки переноса приходят из двух источников. Найденные по журналу
    /// изменений NTFS определены при сканировании и хранятся в самой записи
    /// устройства: журнал в результат не сохраняется, и заново их не построить.
    /// Совпадения имён по артефактам считаются здесь и добавляются только для
    /// файлов, о которых журнал ничего не сказал: иначе слабый признак вытеснил
    /// бы из отчёта сильный.
    /// </summary>
    private static List<CopyIndication> MergeCopyIndications(
        UsbDeviceRecord device,
        IReadOnlyCollection<DeviceActivityEntry> entries,
        DeviceLinkKeys keys,
        IReadOnlyCollection<EvidenceRecord> evidence)
    {
        var merged = new List<CopyIndication>(device.CopyIndications);
        var known = merged
            .Select(x => x.FileName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        merged.AddRange(CopyIndicationFinder.Find(entries, keys, evidence)
            .Where(x => !known.Contains(x.FileName)));

        return merged
            .OrderByDescending(x => ConfidenceRank(x.Confidence))
            .ThenByDescending(x => x.SeenLocallyUtc)
            .ToList();
    }

    /// <summary>
    /// Один и тот же путь Windows сохраняет и в BagMRU, и в ярлыке, и в списке
    /// последних документов. В истории он должен встречаться один раз на момент
    /// времени, иначе список раздувается повторами одного действия.
    /// </summary>
    private static IEnumerable<DeviceActivityEntry> Deduplicate(IEnumerable<DeviceActivityEntry> entries) =>
        entries
            .GroupBy(x => (x.Kind, Path: x.Path.ToUpperInvariant(), Minute: Truncate(x.TimestampUtc)))
            .Select(group => group.OrderByDescending(x => ConfidenceRank(x.LinkConfidence)).First());

    private static DateTimeOffset Truncate(DateTimeOffset value) =>
        new(value.Year, value.Month, value.Day, value.Hour, value.Minute, 0, value.Offset);

    private static int ConfidenceRank(string confidence) => confidence switch
    {
        "High" => 2,
        "Medium" => 1,
        _ => 0
    };

    /// <summary>
    /// Сводные записи корреляции программа создаёт сама на основе других улик.
    /// В историю действий они попадать не должны: это не действие пользователя.
    /// </summary>
    private static bool IsDerivedSummary(EvidenceRecord record) =>
        record.Source.Equals("Correlation", StringComparison.OrdinalIgnoreCase)
        || record.Source.Equals("Volume Correlation", StringComparison.OrdinalIgnoreCase)
        || record.Source.StartsWith("Идентификатор диска", StringComparison.OrdinalIgnoreCase);

    internal static string ClassifyKind(EvidenceRecord record)
    {
        var source = record.Source;
        if (source.Contains("Shellbag", StringComparison.OrdinalIgnoreCase)
            || source.Contains("LastVisitedPidlMRU", StringComparison.OrdinalIgnoreCase))
        {
            return DeviceActivityKind.FolderBrowse;
        }

        if (source.Contains("TypedPaths", StringComparison.OrdinalIgnoreCase))
        {
            return DeviceActivityKind.FolderTyped;
        }

        if (source.Contains("OpenSavePidlMRU", StringComparison.OrdinalIgnoreCase))
        {
            return DeviceActivityKind.FileDialog;
        }

        if (source.Contains("RecentDocs", StringComparison.OrdinalIgnoreCase)
            || source.Contains("LNK", StringComparison.OrdinalIgnoreCase)
            || source.Contains("JumpList", StringComparison.OrdinalIgnoreCase))
        {
            return DeviceActivityKind.FileOpen;
        }

        if (source.Contains("Recycle", StringComparison.OrdinalIgnoreCase))
        {
            return DeviceActivityKind.FileDelete;
        }

        if (source.Contains("WordWheelQuery", StringComparison.OrdinalIgnoreCase))
        {
            return DeviceActivityKind.Search;
        }

        if (source.Contains("MountPoints2", StringComparison.OrdinalIgnoreCase))
        {
            return DeviceActivityKind.Mount;
        }

        // Amcache и Shimcache — артефакты присутствия файла, а не исполнения:
        // их заполняет фоновый сканер совместимости (Compatibility Appraiser),
        // а метка Shimcache — это дата модификации самого файла. Показывать их
        // как «Запускали программу» значит рисовать в истории запуски, которых
        // не было, — в том числе ночью, когда работал только планировщик задач.
        if (source.Contains("Amcache", StringComparison.OrdinalIgnoreCase)
            || source.Contains("Shimcache", StringComparison.OrdinalIgnoreCase))
        {
            return DeviceActivityKind.ProgramPresence;
        }

        if (source.Contains("Prefetch", StringComparison.OrdinalIgnoreCase)
            || source.Contains("UserAssist", StringComparison.OrdinalIgnoreCase)
            || source.Contains("MuiCache", StringComparison.OrdinalIgnoreCase)
            || source.Contains("BAM", StringComparison.OrdinalIgnoreCase)
            || source.Contains("DAM", StringComparison.OrdinalIgnoreCase))
        {
            return DeviceActivityKind.ProgramRun;
        }

        return record.CanEstablishConnectionDate
            ? DeviceActivityKind.Connection
            : DeviceActivityKind.Unknown;
    }

    /// <summary>
    /// У каждого артефакта своя отметка времени, и означают они разное. Ярлык
    /// хранит момент последнего открытия файла, ключ реестра — момент последней
    /// записи в ветку, а корзина — момент удаления. Без этой оговорки строки
    /// истории читаются как точное время действия, чем они не являются.
    /// </summary>
    internal static string DescribeTimeMeaning(EvidenceRecord record)
    {
        var source = record.Source;
        if (source.Contains("LNK", StringComparison.OrdinalIgnoreCase))
        {
            return "Момент последней записи ярлыка — обычно последнее открытие файла";
        }

        if (source.Contains("JumpList", StringComparison.OrdinalIgnoreCase))
        {
            return "Момент обращения к файлу по записи списка переходов";
        }

        if (source.Contains("Recycle", StringComparison.OrdinalIgnoreCase))
        {
            return "Момент удаления файла в корзину";
        }

        if (source.Contains("Shimcache", StringComparison.OrdinalIgnoreCase))
        {
            return "Дата модификации самого файла, а не запуска: файл мог быть изменён задолго до попадания на диск";
        }

        if (source.Contains("Amcache", StringComparison.OrdinalIgnoreCase))
        {
            return "Момент записи фоновым сканером совместимости — не момент запуска программы";
        }

        if (record.RegistryLastWriteUtc.HasValue)
        {
            return "Момент последней записи в ветку реестра: относится ко всей ветке, "
                   + "а не обязательно к этой строке";
        }

        return "Отметка времени артефакта; точный момент действия он может не сохранять";
    }

    /// <summary>
    /// В подсказке артефакта лежит уже разобранный путь. Если её нет, годится
    /// краткое описание, но не сырой текст: он не для чтения.
    /// </summary>
    private static string ChoosePath(EvidenceRecord record) =>
        record.DeviceHint.Length > 0 ? record.DeviceHint : record.Summary;

    [GeneratedRegex(@"(?<![A-Z0-9])(?<drive>[A-Z]):(?:\\|$|\s)", RegexOptions.IgnoreCase)]
    internal static partial Regex DriveLetterRegex();

    [GeneratedRegex(@"(?:VolumeSerial(?:Number)?|VSN)\s*[=:]\s*(?<value>[0-9A-F]{4,16}(?:-[0-9A-F]{4,16})?)",
        RegexOptions.IgnoreCase)]
    internal static partial Regex VolumeSerialRegex();
}
