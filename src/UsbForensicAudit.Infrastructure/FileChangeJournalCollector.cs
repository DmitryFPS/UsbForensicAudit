using System.IO;

namespace UsbForensicAudit;

/// <summary>
/// Собирает из журналов изменений NTFS появление, переименование и удаление
/// файлов на внутренних дисках.
///
/// Нужно это ровно для одного вывода: Windows не журналирует копирование, но
/// журнал файловой системы хранит момент появления файла на диске. Если файл с
/// тем же именем в это же время открывали на съёмном носителе, перенос перестаёт
/// быть догадкой.
///
/// Журнал на большом диске содержит миллионы записей, поэтому отбор идёт сразу:
/// интересуют только события с файлами, у которых есть осмысленное имя, и только
/// вне служебных каталогов Windows. Восстановление пути — самая дорогая часть,
/// поэтому оно выполняется уже после отбора и с запоминанием каталогов.
/// </summary>
public sealed class FileChangeJournalCollector : IFileSystemChangeCollector
{
    /// <summary>
    /// Сколько записей журнала прочитать с одного тома. Ограничение защищает от
    /// многочасового чтения на дисках с огромным журналом; о срезе сообщается.
    /// </summary>
    public const int MaxRecordsPerVolume = 2_000_000;

    /// <summary>Сколько отобранных записей оставить с одного тома.</summary>
    public const int MaxKeptPerVolume = 200_000;

    private static readonly string[] IgnoredPathParts =
    [
        @"\Windows\", @"\Program Files\", @"\Program Files (x86)\", @"\ProgramData\Package Cache\",
        @"\AppData\Local\Temp\", @"\AppData\Local\Packages\", @"\AppData\Local\Microsoft\Windows\INetCache\",
        @"\AppData\Local\Microsoft\Windows\WebCache\", @"\AppData\Local\CrashDumps\",
        @"\AppData\Roaming\Microsoft\Windows\Recent\", @"\System Volume Information\",
        @"\$Recycle.Bin\", @"\AppData\Local\Google\Chrome\User Data\", @"\AppData\Local\Microsoft\Edge\",
        @"\AppData\Local\Temporary Internet Files\", @"\AppData\LocalLow\", @"\Windows.old\"
    ];

    private static readonly string[] IgnoredExtensions =
    [
        ".tmp", ".temp", ".log", ".etl", ".evtx", ".dmp", ".pf", ".db-wal", ".db-shm", ".journal",
        ".lock", ".partial", ".crdownload", ".~tmp", ".bak~", ".ldb", ".idx", ".manifest", ".cat",
        ".mui", ".pri", ".pdb", ".nls", ".blf", ".regtrans-ms", ".chk", ".dat"
    ];

    private readonly IPrivilegeChecker _privileges;

    public FileChangeJournalCollector(IPrivilegeChecker privileges)
    {
        _privileges = privileges;
    }

    public string ProgressMessage => "Чтение журналов изменений NTFS для поиска признаков переноса файлов...";

    public bool ShouldRun => _privileges.IsAdministrator();

    public FileSystemChangeSet Collect(List<string> warnings, CancellationToken cancellationToken = default)
    {
        var changes = new List<FileChangeRecord>();
        var states = new List<FileChangeJournalState>();

        foreach (var volume in InternalNtfsVolumes(warnings))
        {
            cancellationToken.ThrowIfCancellationRequested();
            states.Add(CollectVolume(volume, changes, warnings, cancellationToken));
        }

        if (states.Count == 0)
        {
            warnings.Add("Внутренних томов NTFS для чтения журнала изменений не найдено.");
        }

        return new FileSystemChangeSet(changes, states);
    }

    private FileChangeJournalState CollectVolume(
        string driveLetter,
        List<FileChangeRecord> changes,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        var state = new FileChangeJournalState { Volume = driveLetter };
        using var reader = UsnJournalReader.TryOpen(driveLetter, out var reason);
        if (reader is null)
        {
            state.Note = reason;
            warnings.Add($"Журнал изменений {driveLetter}: {reason}");
            return state;
        }

        state.Available = true;
        var directories = new Dictionary<ulong, string>();
        var seen = new HashSet<(ulong Parent, string Name, string Kind, long Second)>();
        var read = 0;
        var kept = 0;

        try
        {
            foreach (var entry in reader.Read(MaxRecordsPerVolume, cancellationToken))
            {
                read++;
                state.OldestRecordUtc ??= entry.TimestampUtc;
                state.NewestRecordUtc = entry.TimestampUtc;

                if (kept >= MaxKeptPerVolume || !IsInteresting(entry) || !IsFirstOfOperation(seen, entry))
                {
                    continue;
                }

                var directory = ResolveDirectory(reader, directories, entry.ParentFileReferenceNumber);
                if (directory.Length > 0 && IsIgnoredPath(directory))
                {
                    continue;
                }

                changes.Add(new FileChangeRecord
                {
                    TimestampUtc = entry.TimestampUtc,
                    Kind = DescribeKind(entry),
                    FileName = entry.FileName,
                    Path = directory.Length > 0
                        ? Path.Combine(directory, entry.FileName)
                        : entry.FileName,
                    Volume = reader.Volume,
                    Usn = entry.Usn
                });
                kept++;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            state.Note = $"Чтение прервано: {ex.Message}";
            warnings.Add($"Журнал изменений {driveLetter}: чтение прервано: {ex.Message}");
        }

        state.RecordsRead = read;
        state.RecordsKept = kept;
        if (read >= MaxRecordsPerVolume)
        {
            state.Note = $"Достигнут лимит {MaxRecordsPerVolume} записей журнала: более старые события не читались.";
            warnings.Add($"Журнал изменений {driveLetter}: достигнут лимит {MaxRecordsPerVolume} записей.");
        }
        else if (kept >= MaxKeptPerVolume)
        {
            state.Note = $"Достигнут лимит {MaxKeptPerVolume} отобранных событий.";
            warnings.Add($"Журнал изменений {driveLetter}: достигнут лимит {MaxKeptPerVolume} отобранных событий.");
        }

        return state;
    }

    /// <summary>
    /// Одно действие с файлом порождает в журнале несколько записей: сначала
    /// «создан», потом «создан и записан», потом «создан, записан и закрыт».
    /// Причины в записи накапливаются, поэтому все эти записи выглядят как
    /// создание. В историю нужна одна из них, иначе список раздувается повторами
    /// одного события.
    ///
    /// Свёртка идёт с точностью до секунды, а не по файлу целиком: файл могли
    /// создать, удалить и создать заново, и это разные события, которые нельзя
    /// потерять.
    /// </summary>
    private static bool IsFirstOfOperation(
        HashSet<(ulong Parent, string Name, string Kind, long Second)> seen, UsnJournalEntry entry) =>
        seen.Add((
            entry.ParentFileReferenceNumber,
            entry.FileName,
            DescribeKind(entry),
            entry.TimestampUtc.UtcTicks / TimeSpan.TicksPerSecond));

    /// <summary>
    /// Восстановление пути стоит системного вызова на каталог, а файлов в одном
    /// каталоге тысячи. Поэтому каталоги запоминаются, включая неудачи: у
    /// удалённого каталога путь не восстановить, и пытаться заново незачем.
    /// </summary>
    private static string ResolveDirectory(
        UsnJournalReader reader, Dictionary<ulong, string> cache, ulong parentReference)
    {
        if (cache.TryGetValue(parentReference, out var cached))
        {
            return cached;
        }

        var resolved = reader.ResolveDirectory(parentReference);
        cache[parentReference] = resolved;
        return resolved;
    }

    internal static bool IsInteresting(UsnJournalEntry entry)
    {
        if (entry.IsDirectory || !(entry.IsCreate || entry.IsRename || entry.IsDelete))
        {
            return false;
        }

        var name = entry.FileName;
        var dot = name.LastIndexOf('.');
        if (dot <= 0 || dot == name.Length - 1)
        {
            return false;
        }

        var extension = name[dot..];
        if (extension.Length > 6 || IgnoredExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        // Имена вида «~$отчёт.docx» и «AAAAA.tmp.1» создаются программами, а не
        // человеком: в вопросе о переносе файлов они только шумят.
        return !name.StartsWith("~$", StringComparison.Ordinal)
               && !name.StartsWith('.')
               && name.Length >= 5;
    }

    internal static bool IsIgnoredPath(string path) =>
        IgnoredPathParts.Any(part => path.Contains(part, StringComparison.OrdinalIgnoreCase));

    private static string DescribeKind(UsnJournalEntry entry) =>
        entry.IsCreate ? FileChangeKind.Created
        : entry.IsRename ? FileChangeKind.Renamed
        : FileChangeKind.Deleted;

    /// <summary>
    /// Съёмные носители пропускаются: их журнал говорит о том, что делали на
    /// самом носителе, а вопрос стоит о появлении файлов на этой машине.
    /// </summary>
    private static IEnumerable<string> InternalNtfsVolumes(List<string> warnings)
    {
        DriveInfo[] drives;
        try
        {
            drives = DriveInfo.GetDrives();
        }
        catch (Exception ex)
        {
            warnings.Add($"Не удалось перечислить диски: {ex.Message}");
            yield break;
        }

        foreach (var drive in drives)
        {
            string format;
            try
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady)
                {
                    continue;
                }

                format = drive.DriveFormat;
            }
            catch (Exception ex)
            {
                warnings.Add($"Диск {drive.Name}: не удалось определить файловую систему: {ex.Message}");
                continue;
            }

            if (format.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
            {
                yield return drive.Name.TrimEnd('\\');
            }
        }
    }
}
