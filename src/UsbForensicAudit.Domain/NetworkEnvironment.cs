using System.Text.Json.Serialization;

namespace UsbForensicAudit;

/// <summary>Как устройство в сети было найдено.</summary>
public static class NeighborDiscovery
{
    /// <summary>Windows сама записала соседа: машина с ним уже разговаривала.</summary>
    public const string NeighborTable = "NeighborTable";

    /// <summary>Сосед ответил на запрос, посланный этой программой.</summary>
    public const string ActiveProbe = "ActiveProbe";

    /// <summary>Адрес взят из настроек самой машины: шлюз, сервер DHCP или DNS.</summary>
    public const string Configuration = "Configuration";

    public static string Describe(string? value) => value switch
    {
        NeighborTable => "Windows сама записала: машина с ним обменивалась данными",
        ActiveProbe => "Ответил на запрос программы",
        Configuration => "Записан в настройках сети этой машины",
        _ => "Способ обнаружения не записан"
    };
}

/// <summary>Чем устройство приходится этой машине и этой сети.</summary>
public static class NeighborRole
{
    public const string ThisMachine = "ThisMachine";
    public const string Gateway = "Gateway";
    public const string DhcpServer = "DhcpServer";
    public const string DnsServer = "DnsServer";
    public const string Neighbor = "Neighbor";

    public static string Describe(string? value) => value switch
    {
        ThisMachine => "Эта машина",
        Gateway => "Шлюз: через него сеть выходит наружу",
        DhcpServer => "Сервер, раздающий адреса в этой сети",
        DnsServer => "Сервер имён",
        _ => "Устройство в той же сети"
    };

    public static int Rank(string? value) => value switch
    {
        ThisMachine => 0,
        Gateway => 1,
        DhcpServer => 2,
        DnsServer => 3,
        _ => 4
    };
}

/// <summary>
/// Сеть Wi-Fi, которую радиомодуль машины слышит в эфире прямо сейчас.
///
/// Это снимок обстановки на момент сканирования, а не история: список
/// меняется от минуты к минуте и от того, где стоит машина. Путать его с
/// журналом подключений нельзя — слышать сеть и подключаться к ней разные
/// вещи, и одно не доказывает другого.
/// </summary>
public sealed class WirelessNetworkRecord
{
    /// <summary>Имя сети. Пусто у сети, которая своё имя не объявляет.</summary>
    public string Ssid { get; set; } = "";

    /// <summary>Аппаратный адрес точки доступа: он отличает роутер от телефона с тем же именем сети.</summary>
    public string Bssid { get; set; } = "";

    public string Security { get; set; } = "";

    /// <summary>Уровень сигнала, от 0 до 100. Косвенно говорит о расстоянии до точки.</summary>
    public int SignalPercent { get; set; }

    public int Channel { get; set; }

    /// <summary>Диапазон: 2,4 ГГц, 5 ГГц или 6 ГГц.</summary>
    public string Band { get; set; } = "";

    /// <summary>Машина сейчас подключена именно к этой сети.</summary>
    public bool IsConnected { get; set; }

    /// <summary>На машине сохранён профиль этой сети: к ней уже подключались.</summary>
    public bool HasSavedProfile { get; set; }

    public string Adapter { get; set; } = "";

    public DateTimeOffset SeenAtUtc { get; set; } = DateTimeOffset.UtcNow;

    [JsonIgnore]
    public string SsidText => Ssid.Length > 0 ? Ssid : "Имя не объявлено (скрытая сеть)";

    [JsonIgnore]
    public string BssidText => Bssid.Length > 0 ? Bssid : "Адрес точки доступа не получен";

    /// <summary>Кто сделал точку доступа — по началу её аппаратного адреса.</summary>
    [JsonIgnore]
    public string VendorText => MacVendorCatalog.Describe(Bssid);

    [JsonIgnore]
    public string SecurityText => Security.Length > 0 ? Security : "Способ защиты не объявлен";

    [JsonIgnore]
    public string SignalText => $"{SignalPercent}%";

    [JsonIgnore]
    public string ChannelText => Channel > 0
        ? Band.Length > 0 ? $"{Channel} ({Band})" : Channel.ToString()
        : Band.Length > 0 ? Band : "не определён";

    /// <summary>
    /// Как эта сеть связана с машиной. Сохранённый профиль — единственное в
    /// этой таблице, что говорит о прошлом: к сети когда-то подключались.
    /// </summary>
    [JsonIgnore]
    public string RelationText => IsConnected
        ? "Подключена сейчас"
        : HasSavedProfile
            ? "К этой сети подключались: на машине сохранён её профиль"
            : "Просто слышна в эфире";

    [JsonIgnore]
    public string SeenAtText => DateDisplay.FormatMoscow(SeenAtUtc);
}

/// <summary>
/// Устройство, найденное в той же сети, что и эта машина.
///
/// Список никогда не бывает полным. Устройство попадает в него, только если
/// машина с ним разговаривала или если оно ответило на запрос программы.
/// Выключенное, спящее или намеренно молчащее устройство не увидит никто.
/// </summary>
public sealed class NetworkNeighborRecord
{
    public string IpAddress { get; set; } = "";

    public string MacAddress { get; set; } = "";

    /// <summary>Имя из обратной записи DNS, если сеть его отдаёт.</summary>
    public string HostName { get; set; } = "";

    /// <summary>Имя, которым устройство само называется по NetBIOS.</summary>
    public string NetbiosName { get; set; } = "";

    public string Role { get; set; } = NeighborRole.Neighbor;

    public string Discovery { get; set; } = NeighborDiscovery.NeighborTable;

    /// <summary>Состояние записи в таблице соседей Windows: свежая, устаревшая, недостижимая.</summary>
    public string State { get; set; } = "";

    /// <summary>Через какой адаптер этой машины виден сосед.</summary>
    public string Adapter { get; set; } = "";

    /// <summary>Сеть, в которой найден сосед: адрес подсети или имя сети Wi-Fi.</summary>
    public string Network { get; set; } = "";

    public DateTimeOffset SeenAtUtc { get; set; } = DateTimeOffset.UtcNow;

    [JsonIgnore]
    public string AddressText => IpAddress.Length > 0 ? IpAddress : "Адрес не записан";

    [JsonIgnore]
    public string MacText => MacAddress.Length > 0 ? MacAddress : "Аппаратный адрес не получен";

    [JsonIgnore]
    public string VendorText => MacVendorCatalog.Describe(MacAddress);

    /// <summary>
    /// Как устройство себя называет. Имени может не быть вовсе: телефоны и
    /// умная техника обычно не отвечают ни на DNS, ни на NetBIOS.
    /// </summary>
    [JsonIgnore]
    public string NameText
    {
        get
        {
            if (HostName.Length > 0 && NetbiosName.Length > 0
                && !HostName.StartsWith(NetbiosName, StringComparison.OrdinalIgnoreCase))
            {
                return $"{HostName} ({NetbiosName})";
            }

            if (HostName.Length > 0)
            {
                return HostName;
            }

            return NetbiosName.Length > 0 ? NetbiosName : "Имя не отвечает";
        }
    }

    [JsonIgnore]
    public string RoleText => NeighborRole.Describe(Role);

    [JsonIgnore]
    public string DiscoveryText => NeighborDiscovery.Describe(Discovery);

    [JsonIgnore]
    public string StateText => State.Length > 0 ? State : "не записано";

    [JsonIgnore]
    public string NetworkText => Network.Length > 0 ? Network : "сеть не определена";

    [JsonIgnore]
    public string AdapterText => Adapter.Length > 0 ? Adapter : "адаптер не определён";

    /// <summary>
    /// Пояснение к аппаратному адресу. Случайный адрес — не редкость и не
    /// признак злого умысла: так с завода настроены телефоны, и в другой раз
    /// то же устройство придёт под другим адресом.
    /// </summary>
    [JsonIgnore]
    public string MacMeaningText => MacAddress.Length == 0
        ? "Аппаратный адрес не получен"
        : global::UsbForensicAudit.MacAddress.IsLocallyAssigned(MacAddress)
            ? "Адрес назначен на месте, а не заводом: устройство скрывает свой постоянный адрес. "
              + "Опознавать устройство по нему нельзя — в другой раз оно придёт под другим адресом."
            : "Адрес выдан заводом и закреплён за устройством.";

    [JsonIgnore]
    public string SeenAtText => DateDisplay.FormatMoscow(SeenAtUtc);
}

/// <summary>
/// Сеть, к которой машина подключена сейчас, глазами самой машины: свой
/// адрес, маска, шлюз, серверы имён.
/// </summary>
public sealed class NetworkAdapterRecord
{
    public string Name { get; set; } = "";

    public string Description { get; set; } = "";

    public string MacAddress { get; set; } = "";

    public string Kind { get; set; } = NetworkConnectionKind.Unknown;

    public string ConnectedSsid { get; set; } = "";

    public List<string> Addresses { get; set; } = [];

    public List<string> Gateways { get; set; } = [];

    public List<string> DnsServers { get; set; } = [];

    public string DhcpServer { get; set; } = "";

    /// <summary>Адрес сети с длиной маски: «192.168.1.0/24».</summary>
    public string Subnet { get; set; } = "";

    [JsonIgnore]
    public string NameText => Description.Length > 0 ? Description : Name;

    [JsonIgnore]
    public string KindText => NetworkConnectionKind.Describe(Kind);

    [JsonIgnore]
    public string AddressesText => Addresses.Count > 0 ? string.Join(", ", Addresses) : "адрес не назначен";

    [JsonIgnore]
    public string GatewayText => Gateways.Count > 0 ? string.Join(", ", Gateways) : "шлюза нет";

    [JsonIgnore]
    public string DnsText => DnsServers.Count > 0 ? string.Join(", ", DnsServers) : "серверы имён не заданы";

    [JsonIgnore]
    public string SubnetText => Subnet.Length > 0 ? Subnet : "подсеть не определена";
}

/// <summary>
/// Обстановка вокруг машины на момент сканирования: какие сети Wi-Fi слышны и
/// какие устройства видны в той же сети.
///
/// Всё, что здесь есть, — снимок текущего состояния. Windows не хранит списка
/// соседей по сети, поэтому узнать, кто сидел на этом Wi-Fi неделю назад,
/// нельзя ниоткуда. Единственное, что говорит о прошлом, — сохранённые
/// профили сетей и аппаратные адреса их шлюзов, и они собираются отдельно, во
/// вкладке сетевых подключений.
/// </summary>
public sealed class NetworkEnvironmentSnapshot
{
    public DateTimeOffset? TakenAtUtc { get; set; }

    /// <summary>
    /// Программа сама рассылала запросы устройствам сети. Без этого признака
    /// список соседей нельзя правильно прочитать: пустой список означает то
    /// «мы не спрашивали», то «никто не ответил».
    /// </summary>
    public bool ActiveProbeUsed { get; set; }

    /// <summary>Сколько адресов было опрошено, если опрос выполнялся.</summary>
    public int ProbedAddresses { get; set; }

    public List<WirelessNetworkRecord> WirelessNetworks { get; set; } = [];

    public List<NetworkNeighborRecord> Neighbors { get; set; } = [];

    public List<NetworkAdapterRecord> Adapters { get; set; } = [];

    public List<string> Warnings { get; set; } = [];

    [JsonIgnore]
    public bool IsEmpty => TakenAtUtc is null;

    [JsonIgnore]
    public string TakenAtText => TakenAtUtc is null
        ? "Обстановка не снималась"
        : DateDisplay.FormatMoscow(TakenAtUtc.Value);

    /// <summary>
    /// Одна фраза для вкладки и отчётов. Отдельно сказано, был ли опрос сети:
    /// от этого зависит, что означает короткий список соседей.
    /// </summary>
    public string Describe()
    {
        if (IsEmpty)
        {
            return "Обстановка вокруг машины не снималась. Список сетей Wi-Fi и устройств в сети — "
                   + "это состояние на момент съёмки, поэтому он собирается отдельной кнопкой, а не при сканировании.";
        }

        var connected = WirelessNetworks.Count(x => x.IsConnected);
        var known = WirelessNetworks.Count(x => x.HasSavedProfile);
        var named = Neighbors.Count(x => x.HostName.Length > 0 || x.NetbiosName.Length > 0);

        var wireless = WirelessNetworks.Count == 0
            ? "Сетей Wi-Fi в эфире не слышно (или в машине нет радиомодуля)."
            : $"Сетей Wi-Fi в эфире: {WirelessNetworks.Count}"
              + (connected > 0 ? ", из них подключена 1" : "")
              + (known > 0 ? $", знакомых машине — {known}" : "")
              + ".";

        var neighbours = ActiveProbeUsed
            ? $"Устройств в сети найдено: {Neighbors.Count} (опрошено адресов: {ProbedAddresses}), "
              + $"из них назвали имя — {named}."
            : $"Устройств в сети видно: {Neighbors.Count} — только те, с кем машина уже обменивалась данными. "
              + "Опрос сети не проводился, поэтому молчащие устройства сюда не попали.";

        return $"Снято {TakenAtText}. {wireless} {neighbours}";
    }
}
