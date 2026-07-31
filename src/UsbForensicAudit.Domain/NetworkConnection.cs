using System.Text.Json.Serialization;

namespace UsbForensicAudit;

/// <summary>
/// Виды связи, по которым машина обменивалась данными с внешним миром.
///
/// Разделение сделано по тому, что человек увидит в отчёте, а не по тому, из
/// какого артефакта запись пришла: сеть Wi-Fi остаётся сетью Wi-Fi и в реестре,
/// и в журнале службы автонастройки. Отдельно от вида связи стоит вопрос «куда
/// по ней ходили» — на него отвечают обращения внутри записи.
/// </summary>
public static class NetworkConnectionKind
{
    public const string WiFi = "WiFi";
    public const string Wired = "Wired";
    public const string Vpn = "Vpn";
    public const string MobileBroadband = "MobileBroadband";
    public const string Bluetooth = "Bluetooth";
    public const string NetworkShare = "NetworkShare";
    public const string RemoteDesktop = "RemoteDesktop";
    public const string WebSite = "WebSite";
    public const string Nfc = "Nfc";
    public const string Unknown = "Unknown";

    public static string Describe(string? kind) => kind switch
    {
        WiFi => "Сеть Wi-Fi",
        Wired => "Проводная сеть",
        Vpn => "VPN-туннель",
        MobileBroadband => "Мобильный интернет",
        Bluetooth => "Связь по Bluetooth",
        NetworkShare => "Сетевая папка",
        RemoteDesktop => "Удалённый рабочий стол",
        WebSite => "Посещённый сайт",
        Nfc => "Считыватель NFC",
        _ => "Вид связи определить не удалось"
    };

    /// <summary>
    /// Порядок строк во вкладке. Сверху то, чем выносят данные и чем управляют
    /// чужой машиной, затем сами сети, и лишь потом посещённые сайты: их сотни,
    /// и они не должны прятать одну сетевую папку, куда ушли файлы.
    /// </summary>
    public static int Rank(string? kind) => kind switch
    {
        NetworkShare => 0,
        RemoteDesktop => 1,
        WiFi => 2,
        Vpn => 3,
        MobileBroadband => 4,
        Bluetooth => 5,
        Wired => 6,
        Nfc => 7,
        WebSite => 8,
        _ => 9
    };

    public static IReadOnlyList<string> All =>
    [
        NetworkShare, RemoteDesktop, WiFi, Vpn, MobileBroadband,
        Bluetooth, Wired, Nfc, WebSite, Unknown
    ];
}

/// <summary>
/// Куда именно ходили по этой связи: папка на сервере, подключённый диск,
/// адрес сайта. Вид обращения важен читателю: «открывали папку» и «сеть
/// запомнила подключённый диск» — разные по силе следы.
/// </summary>
public static class NetworkVisitKind
{
    public const string Folder = "Folder";
    public const string File = "File";
    public const string MappedDrive = "MappedDrive";
    public const string TypedPath = "TypedPath";
    public const string RememberedShare = "RememberedShare";
    public const string Site = "Site";
    public const string Download = "Download";
    public const string Host = "Host";
    public const string Unknown = "Unknown";

    public static string Describe(string? kind) => kind switch
    {
        Folder => "Открывали папку на сервере",
        File => "Открывали файл на сервере",
        MappedDrive => "Папка была подключена как диск",
        TypedPath => "Путь вводили вручную в адресной строке",
        RememberedShare => "Проводник запомнил сетевую папку",
        Site => "Открывали страницу в браузере",
        Download => "Скачивали файл",
        Host => "Обращались к узлу по сети",
        _ => "Обращение определить не удалось"
    };

    public static int Rank(string? kind) => kind switch
    {
        Folder => 0,
        File => 1,
        MappedDrive => 2,
        TypedPath => 3,
        RememberedShare => 4,
        Download => 5,
        Site => 6,
        Host => 7,
        _ => 8
    };
}

/// <summary>
/// Один сеанс связи: когда соединение установили и когда разорвали. Windows
/// пишет подключение и отключение отдельными событиями, и без их сведения в
/// пары отчёт превращается в столбец одинаковых строк.
/// </summary>
public sealed class NetworkSession
{
    public DateTimeOffset? StartedUtc { get; set; }

    public DateTimeOffset? EndedUtc { get; set; }

    /// <summary>Чем закончилась попытка: соединение установлено, отказ, разрыв.</summary>
    public string Outcome { get; set; } = "";

    /// <summary>Причина разрыва или отказа, если Windows её записала.</summary>
    public string Reason { get; set; } = "";

    /// <summary>Под какой учётной записью шло соединение.</summary>
    public string Account { get; set; } = "";

    public string Source { get; set; } = "";

    public string Provenance { get; set; } = "";

    /// <summary>
    /// Запись об одном событии, а не о сеансе: неудачная попытка соединиться,
    /// обрыв, обращение к серверу. У такой записи конца нет и быть не может, и
    /// «отключение не записано» в её клетке читалось бы как потеря данных, хотя
    /// терять здесь нечего.
    /// </summary>
    public bool IsMoment { get; set; }

    [JsonIgnore]
    public string StartedText => DateDisplay.FormatMoscowOr(StartedUtc, "Начало не записано");

    [JsonIgnore]
    public string EndedText => IsMoment
        ? "Отдельное событие, сеанс не открывался"
        : DateDisplay.FormatMoscowOr(EndedUtc, "Отключение не записано");

    [JsonIgnore]
    public string OutcomeText => ReportText.ForDisplayOrClean(Outcome, 220);

    [JsonIgnore]
    public string ReasonText => ReportText.ForDisplayOrClean(Reason, 400);

    [JsonIgnore]
    public string SourceText => UserDisplayText.Source(Source);

    /// <summary>
    /// Сколько держалось соединение. Пустая строка, когда одного из концов нет:
    /// придумывать длительность по одному событию нельзя.
    /// </summary>
    [JsonIgnore]
    public string DurationText
    {
        get
        {
            if (IsMoment)
            {
                return "не применимо";
            }

            if (StartedUtc is null || EndedUtc is null || EndedUtc <= StartedUtc)
            {
                return "";
            }

            var span = EndedUtc.Value - StartedUtc.Value;
            return span.TotalMinutes < 1
                ? "менее минуты"
                : span.TotalHours < 1
                    ? $"{(int)span.TotalMinutes} мин."
                    : span.TotalDays < 1
                        ? $"{(int)span.TotalHours} ч. {span.Minutes} мин."
                        : $"{(int)span.TotalDays} дн. {span.Hours} ч.";
        }
    }
}

/// <summary>
/// Одно обращение по этой связи: папка на сервере, подключённый диск, адрес
/// страницы. Как и у действий на устройстве, запись всегда несёт источник и
/// значение своей отметки времени — иначе проверить вывод нечем.
/// </summary>
public sealed class NetworkVisit
{
    public DateTimeOffset? WhenUtc { get; set; }

    public string Kind { get; set; } = NetworkVisitKind.Unknown;

    /// <summary>Путь к папке, адрес страницы или имя узла.</summary>
    public string Target { get; set; } = "";

    /// <summary>Заголовок страницы или подпись, если артефакт её сохранил.</summary>
    public string Title { get; set; } = "";

    public string UserSid { get; set; } = "";

    public string ResolvedUserName { get; set; } = "";

    /// <summary>Сколько раз обращение повторялось, если артефакт ведёт счётчик.</summary>
    public int? VisitCount { get; set; }

    public string Source { get; set; } = "";

    /// <summary>Что означает отметка времени именно у этого артефакта.</summary>
    public string TimeMeaning { get; set; } = "";

    public string Provenance { get; set; } = "";

    [JsonIgnore]
    public string WhenText => DateDisplay.FormatMoscowOr(WhenUtc, "Время не записано");

    [JsonIgnore]
    public string KindText => NetworkVisitKind.Describe(Kind);

    [JsonIgnore]
    public string TargetText => NetworkTarget.Describe(Target, Kind);

    [JsonIgnore]
    public string TitleText => ReportText.ForDisplay(Title, 300);

    [JsonIgnore]
    public string UserText => string.IsNullOrWhiteSpace(ResolvedUserName)
        ? (string.IsNullOrWhiteSpace(UserSid) ? "Пользователь не определён" : UserSid)
        : ResolvedUserName;

    [JsonIgnore]
    public string VisitCountText => VisitCount is null or <= 0 ? "" : VisitCount.Value.ToString();

    [JsonIgnore]
    public string SourceText => UserDisplayText.Source(Source);
}

/// <summary>
/// Как показать то, куда ходили.
///
/// Требование к столбцу простое: читатель ждёт путь или адрес и должен получить
/// именно путь или адрес. Адрес страницы длиной в тысячу знаков, служебная схема
/// вида «res://» и пустое значение читаются как мусор, поэтому каждый такой
/// случай назван словами. Само значение остаётся в данных: сокращается только
/// показ.
/// </summary>
public static class NetworkTarget
{
    private const int MaxLength = 400;

    public static string Describe(string? target, string? kind)
    {
        var text = ReportText.ForDisplay(target ?? "", MaxLength);
        if (text.Length == 0)
        {
            return kind == NetworkVisitKind.Site
                ? "Адрес в артефакте не записан"
                : "Путь в артефакте не записан";
        }

        return text;
    }

    /// <summary>
    /// Человекочитаемое имя узла: «20.20.20.76» из «\\20.20.20.76\r0» и
    /// «mail.example.org» из полного адреса страницы. Нужно, чтобы строки одной
    /// и той же машины или сайта собирались в одну запись.
    /// </summary>
    public static string HostOf(string? target)
    {
        var text = (target ?? "").Trim();
        if (text.Length == 0)
        {
            return "";
        }

        if (text.StartsWith(@"\\", StringComparison.Ordinal))
        {
            var rest = text[2..];
            var end = rest.IndexOf('\\');
            return end < 0 ? rest : rest[..end];
        }

        if (Uri.TryCreate(text, UriKind.Absolute, out var uri) && uri.Host.Length > 0)
        {
            return uri.Host;
        }

        return text;
    }

    /// <summary>Похоже ли значение на адрес сетевой папки вида «\\сервер\ресурс».</summary>
    public static bool IsUncPath(string? value) =>
        (value ?? "").TrimStart().StartsWith(@"\\", StringComparison.Ordinal);

    /// <summary>
    /// Имя сервера из журнала SMB. Windows пишет его то с одной ведущей чертой
    /// («\20.20.20.76»), то с ресурсом («\20.20.20.76\r0»), то вовсе подставляет
    /// вместо сервера имя сетевого устройства («\Device\NetBT_Tcpip_{...}»).
    /// Последнее сервером не является, и в отчёте такой строке места нет.
    /// </summary>
    public static bool TryReadServer(string? value, out string host, out string share)
    {
        host = "";
        share = "";
        var text = (value ?? "").Trim().TrimStart('\\');
        if (text.Length == 0
            || text.StartsWith("Device", StringComparison.OrdinalIgnoreCase)
            || text.Contains("NetBT", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var parts = text.Split('\\', 2, StringSplitOptions.TrimEntries);
        if (!LooksLikeHost(parts[0]) || IsLoopback(parts[0]))
        {
            return false;
        }

        host = parts[0];
        share = parts.Length > 1 ? parts[1] : "";
        return true;
    }

    /// <summary>
    /// Собственная машина — не тот, «к кому подключались». Обращение к себе
    /// самой Windows пишет постоянно, и в списке связей это только шум.
    /// </summary>
    public static bool IsLoopback(string? host)
    {
        var text = (host ?? "").Trim().Trim('[', ']');
        return text.Equals("localhost", StringComparison.OrdinalIgnoreCase)
               || text.Equals("127.0.0.1", StringComparison.Ordinal)
               || text.Equals("::1", StringComparison.Ordinal)
               || text.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Имя-заглушка вместо имени сети. Пока Windows определяет, куда попала
    /// машина, сеть называется «Идентификация...», а если определить не удалось —
    /// «Неопознанная сеть». Это состояние, а не сеть: строка с таким именем в
    /// списке связей выглядела бы отдельной сетью, к которой подключались сотни
    /// раз, хотя за этим именем каждый раз стоит другая сеть.
    /// </summary>
    public static bool IsPlaceholderName(string? name)
    {
        var text = (name ?? "").Trim().TrimEnd('.', '…', ' ');
        return text.Equals("Идентификация", StringComparison.OrdinalIgnoreCase)
               || text.Equals("Неопознанная сеть", StringComparison.OrdinalIgnoreCase)
               || text.Equals("Identifying", StringComparison.OrdinalIgnoreCase)
               || text.Equals("Unidentified network", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Похоже ли значение на адрес или имя узла, а не на служебную строку.</summary>
    public static bool LooksLikeHost(string? value)
    {
        var text = (value ?? "").Trim();
        if (text.Length is < 2 or > 255 || text.Contains(' ') || text.Contains('\\'))
        {
            return false;
        }

        if (System.Net.IPAddress.TryParse(text.Trim('[', ']'), out _))
        {
            return true;
        }

        return text.All(x => char.IsAsciiLetterOrDigit(x) || x is '.' or '-' or '_')
               && text.Any(char.IsAsciiLetter);
    }

    /// <summary>
    /// Служебные ресурсы SMB папками не являются: «IPC$» — канал управления,
    /// «C$» и «ADMIN$» — административный доступ ко всему диску. Разница
    /// существенная: «открывали IPC$» и «открывали папку с документами» —
    /// разные утверждения.
    /// </summary>
    public static bool IsAdministrativeShare(string? share)
    {
        var text = (share ?? "").Trim().TrimEnd('\\');
        return text.Equals("IPC$", StringComparison.OrdinalIgnoreCase)
               || text.Equals("ADMIN$", StringComparison.OrdinalIgnoreCase)
               || (text.Length == 2 && text[1] == '$' && char.IsAsciiLetter(text[0]));
    }
}

/// <summary>
/// Одна связь с внешним миром: сеть Wi-Fi, провод, туннель VPN, пара по
/// Bluetooth, сервер с сетевыми папками, узел удалённого рабочего стола, сайт.
///
/// Строка отвечает на три вопроса: как соединялись, с чем именно и когда. Куда
/// по этой связи ходили, лежит внутри — в списке обращений; когда именно
/// соединялись — в списке сеансов.
/// </summary>
public sealed class NetworkConnectionRecord
{
    public string SessionId { get; set; } = "";

    public string Kind { get; set; } = NetworkConnectionKind.Unknown;

    /// <summary>Имя, которое видит человек: SSID, имя сервера, имя устройства, узел сайта.</summary>
    public string Name { get; set; } = "";

    /// <summary>Адрес: IP, MAC, путь к сетевой папке. Пусто, если Windows его не записала.</summary>
    public string Address { get; set; } = "";

    /// <summary>
    /// Ключ, по которому записи из разных источников считаются одной связью.
    /// Заполняется при слиянии, вручную задавать не нужно.
    /// </summary>
    public string CanonicalKey { get; set; } = "";

    public DateTimeOffset? FirstSeenUtc { get; set; }

    public DateTimeOffset? LastSeenUtc { get; set; }

    /// <summary>Откуда взята первая дата: журнал, реестр, оценка.</summary>
    public string FirstSeenProvenance { get; set; } = "";

    public string LastSeenProvenance { get; set; } = "";

    /// <summary>Чем защищено соединение: WPA2-Personal, открытая сеть, подпись SMB.</summary>
    public string Security { get; set; } = "";

    /// <summary>Через какое устройство шла связь: адаптер Wi-Fi, сетевая карта, радиомодуль.</summary>
    public string Adapter { get; set; } = "";

    /// <summary>Учётная запись, под которой шло соединение, если она записана.</summary>
    public string Account { get; set; } = "";

    public string UserSid { get; set; } = "";

    public string ResolvedUserName { get; set; } = "";

    /// <summary>Кто начал соединение: эта машина или удалённая сторона.</summary>
    public string Direction { get; set; } = NetworkDirection.Unknown;

    /// <summary>Адреса самой машины в этой сети, шлюз, DNS — если известны.</summary>
    public List<string> LocalAddresses { get; set; } = [];

    /// <summary>Пояснение своими словами: что это за связь и что о ней известно.</summary>
    public string Details { get; set; } = "";

    public string Source { get; set; } = "";

    public string Provenance { get; set; } = "";

    public List<NetworkSession> Sessions { get; set; } = [];

    public List<NetworkVisit> Visits { get; set; } = [];

    /// <summary>
    /// Все источники, подтвердившие эту связь. Одна и та же сеть встречается и в
    /// реестре, и в журнале; читателю важно видеть, что вывод не опирается на
    /// один артефакт.
    /// </summary>
    public List<string> Sources { get; set; } = [];

    [JsonIgnore]
    public string KindText => NetworkConnectionKind.Describe(Kind);

    [JsonIgnore]
    public string NameText => ReportText.ForDisplay(Name, 300);

    [JsonIgnore]
    public string AddressText => ReportText.ForDisplay(Address, 300);

    /// <summary>
    /// Куда подключались, одной строкой. Имя без адреса и адрес без имени
    /// одинаково неудобны: у сети Wi-Fi человек ищет SSID, у сетевой папки —
    /// путь, а у сервера полезно и то и другое.
    /// </summary>
    [JsonIgnore]
    public string TargetText
    {
        get
        {
            var name = NameText;
            var address = AddressText;
            if (name.Length == 0)
            {
                return address.Length == 0 ? "Имя и адрес не записаны" : address;
            }

            return address.Length == 0 || address.Equals(name, StringComparison.OrdinalIgnoreCase)
                ? name
                : $"{name} ({address})";
        }
    }

    [JsonIgnore]
    public string FirstSeenText => DateDisplay.FormatMoscowOr(FirstSeenUtc, "Первое подключение не записано");

    [JsonIgnore]
    public string LastSeenText => DateDisplay.FormatMoscowOr(LastSeenUtc, "Последнее подключение не записано");

    /// <summary>
    /// Чем защищено соединение. Пустая клетка здесь читается как «защиты нет»,
    /// хотя означает лишь молчание Windows: способ шифрования туннеля VPN задаёт
    /// его клиент, а у проводного подключения такого понятия нет вовсе.
    /// </summary>
    [JsonIgnore]
    public string SecurityText
    {
        get
        {
            var text = ReportText.ForDisplayOrClean(Security, 220);
            return text.Length > 0 ? text : "Сведений о защите Windows не сохранила";
        }
    }

    [JsonIgnore]
    public string AdapterText => ReportText.ForDisplay(Adapter, 220) is { Length: > 0 } text
        ? text
        : "Через какое устройство шла связь, Windows не записала";

    [JsonIgnore]
    public string AccountText => string.IsNullOrWhiteSpace(ResolvedUserName)
        ? ReportText.ForDisplay(string.IsNullOrWhiteSpace(Account) ? UserSid : Account, 220)
        : ReportText.ForDisplay(ResolvedUserName, 220);

    [JsonIgnore]
    public string DirectionText => NetworkDirection.Describe(Direction);

    [JsonIgnore]
    public string DetailsText => ReportText.ForDisplayOrClean(Details, 800);

    [JsonIgnore]
    public string SourceText => UserDisplayText.Source(Source);

    [JsonIgnore]
    public string SourcesText => Sources.Count == 0
        ? SourceText
        : string.Join("; ", Sources.Select(UserDisplayText.Source).Distinct(StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// Адреса, которые машина получала в этой сети. Пустая клетка здесь читается
    /// как «адресов не было», хотя означает лишь, что параметры этого
    /// подключения к сети привязать не удалось: адрес хранится у сетевого
    /// устройства, а не у самой сети.
    /// </summary>
    [JsonIgnore]
    public string LocalAddressesText => LocalAddresses.Count > 0
        ? string.Join("; ", LocalAddresses)
        : "Адреса этой машины в этой сети Windows не сохранила";

    [JsonIgnore]
    public int SessionCount => Sessions.Count;

    [JsonIgnore]
    public int VisitCount => Visits.Count;

    /// <summary>
    /// Сколько раз соединялись и куда ходили — одной строкой для таблицы.
    /// Пустое значение здесь недопустимо: читатель должен видеть, что записей
    /// нет, а не пустую клетку.
    /// </summary>
    [JsonIgnore]
    public string ActivityText
    {
        get
        {
            var parts = new List<string>();
            if (SessionCount > 0)
            {
                parts.Add($"сеансов — {SessionCount}");
            }

            if (VisitCount > 0)
            {
                parts.Add($"обращений — {VisitCount}");
            }

            return parts.Count == 0 ? "Только сам факт связи" : string.Join(", ", parts);
        }
    }

    /// <summary>Внешняя ли это связь: то, по чему данные могли уйти с машины.</summary>
    [JsonIgnore]
    public bool IsOutsideReach => Kind is NetworkConnectionKind.NetworkShare
        or NetworkConnectionKind.RemoteDesktop
        or NetworkConnectionKind.Vpn
        or NetworkConnectionKind.Bluetooth;
}

/// <summary>
/// Кто начинал соединение. Для отчёта это разные события: сотрудник открыл
/// чужую папку или чужая машина пришла к этой.
/// </summary>
public static class NetworkDirection
{
    public const string Outgoing = "Outgoing";
    public const string Incoming = "Incoming";
    public const string Unknown = "Unknown";

    public static string Describe(string? direction) => direction switch
    {
        Outgoing => "С этой машины наружу",
        Incoming => "К этой машине извне",
        _ => "Направление не определено"
    };
}
