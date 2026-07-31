using System.Text.Json.Serialization;

namespace UsbForensicAudit;

/// <summary>
/// Одно действие, совершённое на конкретном внешнем устройстве: открыли папку,
/// открыли файл, удалили файл, запустили программу. Кроме самого действия
/// запись всегда несёт основание, по которому она отнесена именно к этому
/// устройству, — без него читатель не может проверить вывод.
/// </summary>
public sealed class DeviceActivityEntry
{
    public DateTimeOffset TimestampUtc { get; set; }

    public string Kind { get; set; } = DeviceActivityKind.Unknown;

    /// <summary>Папка или файл, к которому обращались.</summary>
    public string Path { get; set; } = "";

    public string UserSid { get; set; } = "";

    public string ResolvedUserName { get; set; } = "";

    /// <summary>Артефакт Windows, из которого взято действие.</summary>
    public string Source { get; set; } = "";

    /// <summary>
    /// Почему запись отнесена к этому устройству: серийный номер тома, GUID
    /// тома, идентификатор устройства, имя в проводнике или буква диска.
    /// </summary>
    public string LinkBasis { get; set; } = "";

    public string LinkConfidence { get; set; } = "Low";

    /// <summary>Что означает отметка времени у этого артефакта.</summary>
    public string TimeMeaning { get; set; } = "";

    public string Provenance { get; set; } = "";

    [JsonIgnore]
    public string TimestampText => DateDisplay.FormatMoscow(TimestampUtc);

    [JsonIgnore]
    public string KindText => DeviceActivityKind.Describe(Kind);

    [JsonIgnore]
    public string PathText => DeviceActivityTarget.Describe(Path, Kind);

    [JsonIgnore]
    public string UserText => string.IsNullOrWhiteSpace(ResolvedUserName)
        ? (string.IsNullOrWhiteSpace(UserSid) ? "Пользователь не определён" : UserSid)
        : ResolvedUserName;

    [JsonIgnore]
    public string LinkText => $"{LinkBasis} ({DeviceActivityHistory.DescribeConfidence(LinkConfidence)})";

    [JsonIgnore]
    public string SourceText => UserDisplayText.Source(Source);
}

/// <summary>
/// Как показать то, на что указывает запись.
///
/// Папка есть не у каждой записи. Событие подключения называет устройство —
/// «SWD\WPDBUSENUM\_??_USBSTOR#Disk&amp;Ven_General&amp;Prod_UDisk#…», — а запись
/// проводника о подключении тома называет GUID тома. В столбце «Папка или файл»
/// такой идентификатор читался как непонятный путь, хотя никакой папки в этой
/// записи нет и быть не может. Сам идентификатор остаётся в данных: скрыт он
/// только там, где читатель ждёт путь.
/// </summary>
public static class DeviceActivityTarget
{
    public static string Describe(string? path, string? kind)
    {
        var text = ReportText.ForDisplay(path ?? "", 500);
        if (text.Length == 0)
        {
            return "Путь в артефакте не записан";
        }

        return NamesDeviceInsteadOfFolder(text) ? Explain(kind) : text;
    }

    private static string Explain(string? kind) => kind switch
    {
        DeviceActivityKind.Connection => "Папки нет: это запись о подключении или отключении устройства",
        DeviceActivityKind.Mount => "Папки нет: проводник запомнил том, а не папку",
        _ => "Папки нет: артефакт называет устройство, а не папку"
    };

    private static bool NamesDeviceInsteadOfFolder(string text) =>
        TextSanitizer.LooksLikeDeviceIdentifier(text) || IsGuidOnly(text);

    /// <summary>GUID тома целиком, без пути: «{F7821AA0-8B1D-11F1-9B5E-9010376EDA10}».</summary>
    private static bool IsGuidOnly(string text) =>
        text.StartsWith('{') && text.EndsWith('}') && Guid.TryParse(text, out _);
}

/// <summary>
/// Виды действий, которые Windows сохраняет в своих артефактах. Разделены по
/// тому, что именно произошло, а не по тому, из какого файла реестра это взято:
/// читателя интересует «открыли папку», а не «BagMRU».
/// </summary>
public static class DeviceActivityKind
{
    public const string FolderBrowse = "FolderBrowse";
    public const string FolderTyped = "FolderTyped";
    public const string FileOpen = "FileOpen";
    public const string FileDialog = "FileDialog";
    public const string FileDelete = "FileDelete";
    public const string ProgramRun = "ProgramRun";
    public const string Search = "Search";
    public const string Mount = "Mount";
    public const string Connection = "Connection";
    public const string Unknown = "Unknown";

    public static string Describe(string? kind) => kind switch
    {
        FolderBrowse => "Открывали папку в проводнике",
        FolderTyped => "Путь вводили вручную в адресной строке",
        FileOpen => "Открывали файл",
        FileDialog => "Выбирали файл в окне открытия или сохранения",
        FileDelete => "Удаляли файл в корзину",
        ProgramRun => "Запускали программу",
        Search => "Искали по содержимому",
        Mount => "Проводник запомнил подключение тома",
        Connection => "Подключение или отключение устройства",
        _ => "Действие определить не удалось"
    };

    /// <summary>
    /// Порядок разделов в отчёте: сначала то, что говорит о работе с файлами.
    /// </summary>
    public static int Rank(string? kind) => kind switch
    {
        FolderBrowse => 0,
        FolderTyped => 1,
        FileOpen => 2,
        FileDialog => 3,
        FileDelete => 4,
        ProgramRun => 5,
        Search => 6,
        Mount => 7,
        Connection => 8,
        _ => 9
    };
}

/// <summary>
/// Признак того, что файл переносили между устройством и этой машиной.
///
/// Само копирование Windows не журналирует. Но журнал изменений NTFS хранит
/// момент появления файла на внутреннем диске, и если файл с тем же именем в это
/// же время открывали на устройстве — перенос становится обоснованным выводом, а
/// не догадкой. Когда журнала нет, остаётся совпадение имён: это повод проверить.
/// </summary>
public sealed class CopyIndication
{
    public string FileName { get; set; } = "";
    public string PathOnDevice { get; set; } = "";
    public string LocalPath { get; set; } = "";
    public DateTimeOffset? SeenOnDeviceUtc { get; set; }
    public DateTimeOffset? SeenLocallyUtc { get; set; }
    public string Source { get; set; } = "";

    public string Direction { get; set; } = CopyDirection.Unknown;

    /// <summary>На чём основан вывод: журнал изменений или совпадение имён.</summary>
    public string Basis { get; set; } = "";

    public string Confidence { get; set; } = "Low";

    [JsonIgnore]
    public string SeenOnDeviceText => DateDisplay.FormatMoscowOr(SeenOnDeviceUtc, "Время неизвестно");

    [JsonIgnore]
    public string SeenLocallyText => DateDisplay.FormatMoscowOr(SeenLocallyUtc, "Время неизвестно");

    [JsonIgnore]
    public string DirectionText => CopyDirection.Describe(Direction);

    [JsonIgnore]
    public string ConfidenceText => DeviceActivityHistory.DescribeConfidence(Confidence);

    /// <summary>
    /// Сколько прошло между работой с файлом на устройстве и его появлением на
    /// внутреннем диске. Короткий промежуток — главный довод в пользу переноса.
    /// </summary>
    [JsonIgnore]
    public string GapText
    {
        get
        {
            if (SeenOnDeviceUtc is null || SeenLocallyUtc is null)
            {
                return "";
            }

            var gap = (SeenLocallyUtc.Value - SeenOnDeviceUtc.Value).Duration();
            return gap.TotalMinutes < 1
                ? "менее минуты"
                : gap.TotalHours < 1
                    ? $"{(int)gap.TotalMinutes} мин."
                    : gap.TotalDays < 1
                        ? $"{(int)gap.TotalHours} ч."
                        : $"{(int)gap.TotalDays} дн.";
        }
    }
}

public static class CopyDirection
{
    /// <summary>Файл появился на внутреннем диске после работы с ним на устройстве.</summary>
    public const string ToComputer = "ToComputer";

    /// <summary>Файл был на внутреннем диске раньше, чем его открыли на устройстве.</summary>
    public const string ToDevice = "ToDevice";

    public const string Unknown = "Unknown";

    public static string Describe(string? direction) => direction switch
    {
        ToComputer => "С устройства на компьютер",
        ToDevice => "С компьютера на устройство",
        _ => "Направление определить нельзя"
    };
}

/// <summary>
/// Всё, что удалось восстановить о работе на одном устройстве.
/// </summary>
public sealed class DeviceActivityHistory
{
    public string DeviceDisplayName { get; set; } = "";
    public string CanonicalDeviceId { get; set; } = "";

    public List<DeviceActivityEntry> Entries { get; set; } = [];

    public List<CopyIndication> CopyIndications { get; set; } = [];

    /// <summary>
    /// По каким признакам вообще можно было искать следы этого устройства.
    /// Если признаков нет, пустая история не означает, что ничего не делали.
    /// </summary>
    public List<string> LinkKeys { get; set; } = [];

    /// <summary>
    /// Есть ли у устройства признак, по которому вообще можно найти работу с
    /// файлами: буква диска, серийный номер тома, GUID тома или видимое имя.
    /// </summary>
    public bool CanSearchFileActivity { get; set; }

    /// <summary>
    /// За какой период удалось прочитать журнал изменений NTFS. Нужен, чтобы
    /// «признаков переноса нет» не читалось шире, чем есть основания.
    /// </summary>
    public List<string> JournalCoverage { get; set; } = [];

    [JsonIgnore]
    public int FolderCount => Entries
        .Where(x => x.Kind is DeviceActivityKind.FolderBrowse or DeviceActivityKind.FolderTyped)
        .Select(x => x.Path)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Count();

    [JsonIgnore]
    public int FileCount => Entries
        .Where(x => x.Kind is DeviceActivityKind.FileOpen or DeviceActivityKind.FileDialog or DeviceActivityKind.FileDelete)
        .Select(x => x.Path)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Count();

    [JsonIgnore]
    public int ProgramCount => Entries
        .Where(x => x.Kind == DeviceActivityKind.ProgramRun)
        .Select(x => x.Path)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Count();

    [JsonIgnore]
    public bool IsEmpty => Entries.Count == 0;

    /// <summary>
    /// Короткий вывод для шапки окна и отчёта. Отдельно оговаривает случай, когда
    /// искать было не по чему: пустая история и отсутствие признаков поиска —
    /// разные вещи, и путать их нельзя.
    /// </summary>
    public string Verdict()
    {
        if (LinkKeys.Count == 0 || !CanSearchFileActivity)
        {
            return "У этого устройства нет ни буквы диска, ни серийного номера тома, ни GUID тома, "
                   + "ни видимого имени в проводнике. Проводник записывает путь вида «E:\\Папка», а не "
                   + "идентификатор устройства, поэтому следы работы с файлами по такому устройству "
                   + "найти нечем. Пустая история здесь означает невозможность поиска, а не отсутствие "
                   + "действий."
                   + (IsEmpty ? "" : $" Найдено {Entries.Count} записей по идентификатору устройства.");
        }

        if (IsEmpty)
        {
            return $"Следов работы с файлами не найдено. Искали по признакам: {string.Join("; ", LinkKeys)}. "
                   + "Это значит, что артефакты проводника не сохранили обращений к этому устройству "
                   + "либо были очищены.";
        }

        var parts = new List<string>();
        if (FolderCount > 0)
        {
            parts.Add($"папок открывали — {FolderCount}");
        }

        if (FileCount > 0)
        {
            parts.Add($"файлов затронуто — {FileCount}");
        }

        if (ProgramCount > 0)
        {
            parts.Add($"программ запускали — {ProgramCount}");
        }

        // Записи о подключении — не работа с файлами. Прежний вывод в этом случае
        // читался как «найдено 8 действий», хотя ни одной папки на устройстве не
        // открывали: все восемь записей говорили только о том, что его втыкали.
        if (parts.Count == 0)
        {
            return $"Следов работы с файлами не найдено: все {Entries.Count} записей — о самом устройстве "
                   + "(подключение, отключение, запомненный том), а не о папках и файлах. "
                   + $"Искали по признакам: {string.Join("; ", LinkKeys)}. Это значит, что артефакты "
                   + "проводника не сохранили обращений к этому устройству либо были очищены.";
        }

        return $"Найдено {Entries.Count} действий: {string.Join(", ", parts)}. "
               + $"Искали по признакам: {string.Join("; ", LinkKeys)}.";
    }

    /// <summary>
    /// Что известно о переносе файлов. Windows не журналирует копирование, но
    /// журнал изменений NTFS хранит момент появления файла на диске. Разница
    /// между «нашли по журналу» и «совпали имена» принципиальна, и вывод обязан
    /// её называть — иначе догадку прочитают как доказательство.
    /// </summary>
    public string CopyVerdict()
    {
        var coverage = JournalCoverage.Count > 0
            ? " " + string.Join(" ", JournalCoverage)
            : " Журнал изменений NTFS прочитать не удалось, поэтому проверка опиралась только на "
              + "совпадение имён файлов.";

        if (CopyIndications.Count == 0)
        {
            return "Признаков переноса файлов не найдено. Windows не ведёт журнал копирования: "
                   + "отсутствие признаков не доказывает, что с устройства ничего не переносили."
                   + coverage;
        }

        var byJournal = CopyIndications.Count(x => x.Confidence != "Low");
        var toComputer = CopyIndications.Count(x => x.Direction == CopyDirection.ToComputer);
        var toDevice = CopyIndications.Count(x => x.Direction == CopyDirection.ToDevice);

        var parts = new List<string>();
        if (toComputer > 0)
        {
            parts.Add($"с устройства на компьютер — {toComputer}");
        }

        if (toDevice > 0)
        {
            parts.Add($"с компьютера на устройство — {toDevice}");
        }

        var undecided = CopyIndications.Count - toComputer - toDevice;
        if (undecided > 0)
        {
            parts.Add($"направление не определено — {undecided}");
        }

        var direction = parts.Count > 0 ? $" ({string.Join(", ", parts)})" : "";
        var basis = byJournal > 0
            ? $" Из них {byJournal} подтверждены журналом изменений NTFS: файл с этим именем "
              + "действительно появился на внутреннем диске, и время согласуется с работой на устройстве."
            : " Все они основаны только на совпадении имён: это повод проверить, а не доказательство.";

        return $"Найдено признаков переноса файлов: {CopyIndications.Count}{direction}."
               + basis + coverage;
    }

    public static string DescribeConfidence(string? confidence) => confidence switch
    {
        "High" => "надёжно",
        "Medium" => "с оговорками",
        _ => "предположительно"
    };
}
