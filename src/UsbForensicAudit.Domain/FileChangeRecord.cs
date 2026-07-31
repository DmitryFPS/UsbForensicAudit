using System.Text.Json.Serialization;

namespace UsbForensicAudit;

/// <summary>
/// Одно изменение файла на внутреннем диске, взятое из журнала изменений NTFS.
/// Журнал ведёт сама файловая система: он не зависит от того, чистил ли кто-то
/// реестр и списки последних документов, и хранит момент появления файла.
/// Именно это позволяет говорить о копировании, которое Windows нигде не
/// журналирует напрямую.
/// </summary>
public sealed class FileChangeRecord
{
    public DateTimeOffset TimestampUtc { get; set; }

    public string Kind { get; set; } = FileChangeKind.Created;

    /// <summary>Полный путь, если каталог удалось восстановить, иначе имя файла.</summary>
    public string Path { get; set; } = "";

    public string FileName { get; set; } = "";

    public string Volume { get; set; } = "";

    /// <summary>Порядковый номер записи в журнале — ссылка на источник.</summary>
    public long Usn { get; set; }

    [JsonIgnore]
    public string TimestampText => DateDisplay.FormatMoscow(TimestampUtc);

    [JsonIgnore]
    public string KindText => FileChangeKind.Describe(Kind);
}

public static class FileChangeKind
{
    public const string Created = "Created";
    public const string Renamed = "Renamed";
    public const string Deleted = "Deleted";

    public static string Describe(string? kind) => kind switch
    {
        Created => "Файл создан",
        Renamed => "Файл переименован или перемещён",
        Deleted => "Файл удалён",
        _ => "Изменение файла"
    };
}

/// <summary>
/// Насколько глубоко удалось заглянуть в журнал изменений тома.
///
/// Журнал имеет ограниченный размер и затирается по кругу: старые записи
/// пропадают. Без указания периода вывод «записи о создании файла нет» читается
/// как «файл не копировали», хотя на деле запись могла просто вытесниться.
/// </summary>
public sealed class FileChangeJournalState
{
    public string Volume { get; set; } = "";

    public bool Available { get; set; }

    public DateTimeOffset? OldestRecordUtc { get; set; }

    public DateTimeOffset? NewestRecordUtc { get; set; }

    public int RecordsRead { get; set; }

    public int RecordsKept { get; set; }

    /// <summary>Почему журнал недоступен или прочитан не полностью.</summary>
    public string Note { get; set; } = "";

    [JsonIgnore]
    public string CoverageText
    {
        get
        {
            if (!Available)
            {
                return $"Том {Volume}: журнал изменений недоступен. {Note}".TrimEnd();
            }

            var from = DateDisplay.FormatMoscowOr(OldestRecordUtc, "неизвестно");
            var to = DateDisplay.FormatMoscowOr(NewestRecordUtc, "неизвестно");
            return $"Том {Volume}: журнал изменений покрывает период с {from} по {to}. "
                   + "Журнал имеет ограниченный размер и затирается по кругу, поэтому события "
                   + "раньше этого периода в нём отсутствуют независимо от того, происходили они или нет."
                   + (Note.Length > 0 ? $" {Note}" : "");
        }
    }
}
