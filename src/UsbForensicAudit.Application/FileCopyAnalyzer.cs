namespace UsbForensicAudit;

/// <summary>
/// Ищет признаки переноса файлов между внешним устройством и этой машиной.
///
/// Windows не журналирует копирование, поэтому прямого ответа нет ни у одного
/// источника. Но два независимых следа вместе дают обоснованный вывод: журнал
/// изменений NTFS хранит момент появления файла на внутреннем диске, а артефакты
/// проводника — момент работы с файлом того же имени на устройстве. Совпадение
/// имени и близость по времени — это уже довод, а не догадка.
///
/// Направление важно не меньше самого факта. Файл, появившийся на диске после
/// работы с ним на носителе, принесли с носителя. Файл, лежавший на диске раньше,
/// чем его открыли на носителе, наоборот, унесли с машины.
/// </summary>
public static class FileCopyAnalyzer
{
    /// <summary>
    /// Промежуток, внутри которого перенос считается подтверждённым. Копирование
    /// занимает секунды или минуты; сутки между событиями с тем же именем — уже
    /// совпадение, а не наблюдаемая последовательность.
    /// </summary>
    public static readonly TimeSpan ConfirmationWindow = TimeSpan.FromMinutes(10);

    public const int MaxIndicationsPerDevice = 200;

    public static void Process(AuditResult result, FileSystemChangeSet changes)
    {
        result.FileChangeJournals = changes.Journals.ToList();
        if (changes.Changes.Count == 0)
        {
            return;
        }

        var changesByName = changes.Changes
            .Where(x => x.Kind != FileChangeKind.Deleted)
            .GroupBy(x => CopyIndicationFinder.FileName(x.FileName), StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Key.Length > 0)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        if (changesByName.Count == 0)
        {
            return;
        }

        // Буквы внутренних томов берутся из того же журнала: том попадает в список
        // и когда журнал на нём выключен. Без этого списка путь «D:\Софт\...»
        // выглядит как путь на устройстве, и файл сопоставляется сам с собой.
        var internalVolumes = changes.Journals
            .Select(x => x.Volume.TrimEnd('\\'))
            .Where(x => x.Length >= 2)
            .Select(x => char.ToUpperInvariant(x[0]))
            .ToHashSet();

        foreach (var device in result.Devices.Where(IsWorthChecking))
        {
            var history = DeviceActivityBuilder.Build(device, result);
            if (history.IsEmpty)
            {
                continue;
            }

            device.CopyIndications = Match(history, changesByName, internalVolumes);
        }
    }

    /// <summary>
    /// Вопрос о переносе файлов имеет смысл только для устройств, которые
    /// приносили с собой. У записи внутреннего диска и у части самой шины
    /// «переносить файлы на устройство» нечему, а буква внутреннего тома
    /// притягивает к такой записи всю локальную файловую активность.
    /// </summary>
    private static bool IsWorthChecking(UsbDeviceRecord device) =>
        device.IsExternalDevice || device.Externality == DeviceExternality.PossiblyExternal;

    private static List<CopyIndication> Match(
        DeviceActivityHistory history,
        Dictionary<string, FileChangeRecord[]> changesByName,
        HashSet<char> internalVolumes)
    {
        var indications = new List<CopyIndication>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in history.Entries.Where(x => !IsOnInternalVolume(x.Path, internalVolumes)))
        {
            var name = CopyIndicationFinder.FileName(entry.Path);
            if (name.Length == 0 || !seen.Add(name) || !changesByName.TryGetValue(name, out var candidates))
            {
                continue;
            }

            var closest = candidates
                .Where(x => !x.Path.Equals(entry.Path, StringComparison.OrdinalIgnoreCase))
                .OrderBy(x => (x.TimestampUtc - entry.TimestampUtc).Duration())
                .FirstOrDefault();
            if (closest is null)
            {
                continue;
            }

            indications.Add(Describe(entry, closest));
            if (indications.Count >= MaxIndicationsPerDevice)
            {
                break;
            }
        }

        return indications
            .OrderByDescending(x => x.Confidence == "High")
            .ThenByDescending(x => x.SeenLocallyUtc)
            .ToList();
    }

    /// <summary>
    /// След может упоминать файл на внутреннем диске, даже если привязан к
    /// внешнему устройству: буква диска за год достаётся разным носителям.
    /// Сравнивать такой путь с журналом внутреннего диска бессмысленно — это
    /// сравнение файла с самим собой.
    /// </summary>
    private static bool IsOnInternalVolume(string path, HashSet<char> internalVolumes)
    {
        if (internalVolumes.Count == 0 || !CopyIndicationFinder.IsLocalDiskPath(path))
        {
            return false;
        }

        return internalVolumes.Contains(char.ToUpperInvariant(path.TrimStart()[0]));
    }

    /// <summary>
    /// Определяет и сам факт переноса, и его направление — насколько это позволяют
    /// данные.
    ///
    /// Близость событий по времени — сильный довод в пользу переноса: файла с
    /// таким именем на диске только что не было, и он появился ровно тогда, когда
    /// работали с носителем. А вот направление из одного порядка событий в этом
    /// случае не выводится: отметки времени артефактов проводника имеют грубую
    /// точность, и разница в несколько секунд может лежать в любую сторону.
    ///
    /// Направление становится видно, когда между событиями заметный промежуток.
    /// Файл, появившийся на диске много позже работы с носителем, принесли с
    /// носителя. Файл, лежавший на диске задолго до этого, унесли с машины.
    /// </summary>
    private static CopyIndication Describe(DeviceActivityEntry entry, FileChangeRecord change)
    {
        var gap = change.TimestampUtc - entry.TimestampUtc;
        var withinWindow = gap.Duration() <= ConfirmationWindow;
        var direction = withinWindow
            ? CopyDirection.Unknown
            : gap > TimeSpan.Zero ? CopyDirection.ToComputer : CopyDirection.ToDevice;

        return new CopyIndication
        {
            FileName = change.FileName,
            PathOnDevice = entry.Path,
            LocalPath = change.Path,
            SeenOnDeviceUtc = entry.TimestampUtc,
            SeenLocallyUtc = change.TimestampUtc,
            Source = $"Журнал изменений NTFS ({change.Volume})",
            Direction = direction,
            Confidence = withinWindow ? "High" : "Medium",
            Basis = BuildBasis(entry, change, direction)
        };
    }

    /// <summary>
    /// Основание пишется словами и целиком: читатель отчёта должен понять, что
    /// именно наблюдалось, и где вывод переходит в предположение.
    /// </summary>
    private static string BuildBasis(DeviceActivityEntry entry, FileChangeRecord change, string direction)
    {
        var action = change.Kind == FileChangeKind.Created
            ? "создан на внутреннем диске"
            : "переименован или перемещён на внутреннем диске";

        var observed = $"Файл {action} по данным журнала изменений NTFS, "
                       + $"а на устройстве файл с этим именем затронут по данным «{entry.SourceText}».";

        return direction switch
        {
            CopyDirection.ToComputer =>
                observed + " Файл появился на диске заметно позже работы с ним на устройстве: "
                         + "порядок событий соответствует переносу с устройства на компьютер.",
            CopyDirection.ToDevice =>
                observed + " Файл лежал на диске задолго до работы с ним на устройстве: "
                         + "порядок событий соответствует переносу с компьютера на устройство.",
            _ =>
                observed + $" Между событиями прошло не больше {(int)ConfirmationWindow.TotalMinutes} минут: "
                         + "файла с таким именем на диске до этого не было, и он появился в момент работы "
                         + "с устройством — это соответствует переносу. Направление по такому короткому "
                         + "промежутку определить нельзя: отметки времени артефактов проводника имеют "
                         + "грубую точность."
        };
    }
}
