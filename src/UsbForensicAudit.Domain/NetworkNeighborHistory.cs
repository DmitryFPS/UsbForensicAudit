using System.Text.Json.Serialization;

namespace UsbForensicAudit;

/// <summary>
/// Одно наблюдение устройства в один снимок обстановки: когда снимали, под
/// каким адресом и как устройство было найдено. Из таких наблюдений
/// складывается история активности устройства за сессию аудита.
/// </summary>
public sealed class NetworkNeighborObservation
{
    public DateTimeOffset TakenAtUtc { get; set; }

    public string IpAddress { get; set; } = "";

    public string Discovery { get; set; } = NeighborDiscovery.NeighborTable;

    /// <summary>Состояние записи в таблице соседей Windows на момент снимка.</summary>
    public string State { get; set; } = "";

    /// <summary>Сеть, в которой устройство было замечено.</summary>
    public string Network { get; set; } = "";

    /// <summary>Имя, которым устройство назвалось в этот раз.</summary>
    public string Name { get; set; } = "";

    [JsonIgnore]
    public string TakenAtText => DateDisplay.FormatMoscow(TakenAtUtc);

    [JsonIgnore]
    public string DiscoveryText => NeighborDiscovery.Describe(Discovery);
}

/// <summary>
/// История активности одного устройства, накопленная за сессию аудита из
/// повторных снимков обстановки.
///
/// Windows не хранит список клиентов Wi-Fi, поэтому единственный честный
/// источник такой истории — наши собственные повторные съёмки: каждая новая
/// съёмка кнопкой «Снять обстановку» добавляет наблюдения сюда, а не
/// перезатирает прошлые. История говорит, когда устройство замечено впервые и
/// в последний раз, сколько раз попадало в снимки, под какими адресами и
/// именами. Устройство со случайным (назначенным на месте) аппаратным адресом
/// опознать между снимками нельзя, и такие наблюдения намеренно не
/// склеиваются — иначе история врала бы.
/// </summary>
public sealed class NetworkNeighborHistory
{
    /// <summary>Ключ склейки наблюдений: заводской MAC, IP или уникальная метка.</summary>
    public string Key { get; set; } = "";

    public string MacAddress { get; set; } = "";

    /// <summary>Адрес назначен на месте, а не заводом: опознание по нему невозможно.</summary>
    public bool IsRandomizedMac { get; set; }

    /// <summary>Устройство опознавалось только по IP: аппаратный адрес не был получен.</summary>
    public bool IdentifiedByIpOnly { get; set; }

    public string Role { get; set; } = NeighborRole.Neighbor;

    public DateTimeOffset FirstSeenUtc { get; set; }

    public DateTimeOffset LastSeenUtc { get; set; }

    /// <summary>В скольких снимках обстановки устройство было замечено.</summary>
    public int TimesSeen { get; set; }

    /// <summary>Все IP-адреса, под которыми устройство было замечено.</summary>
    public List<string> IpAddresses { get; set; } = [];

    /// <summary>Все сети, в которых устройство было замечено.</summary>
    public List<string> Networks { get; set; } = [];

    /// <summary>Все имена, которыми устройство себя называло.</summary>
    public List<string> Names { get; set; } = [];

    public List<NetworkNeighborObservation> Observations { get; set; } = [];

    [JsonIgnore]
    public string MacText => MacAddress.Length > 0 ? MacAddress : "Аппаратный адрес не получен";

    [JsonIgnore]
    public string VendorText => MacVendorCatalog.Describe(MacAddress);

    [JsonIgnore]
    public string RoleText => NeighborRole.Describe(Role);

    [JsonIgnore]
    public string FirstSeenText => DateDisplay.FormatMoscow(FirstSeenUtc);

    [JsonIgnore]
    public string LastSeenText => DateDisplay.FormatMoscow(LastSeenUtc);

    [JsonIgnore]
    public string TimesSeenText => TimesSeen == 1
        ? "1 снимок"
        : $"{TimesSeen} снимков(-а)";

    [JsonIgnore]
    public string IpAddressesText => IpAddresses.Count > 0
        ? string.Join(", ", IpAddresses)
        : "Адрес не записан";

    [JsonIgnore]
    public string NetworksText => Networks.Count > 0
        ? string.Join(", ", Networks)
        : "Сеть не определена";

    [JsonIgnore]
    public string NamesText => Names.Count > 0
        ? string.Join(", ", Names)
        : "Имя не отвечает";

    /// <summary>
    /// Насколько устройству можно доверять как «одному и тому же» между
    /// снимками. Пустой клетки здесь нет: читатель должен видеть, на чём
    /// держится склейка наблюдений.
    /// </summary>
    [JsonIgnore]
    public string IdentityText => IsRandomizedMac
        ? "Ненадёжно: адрес случайный, в другой раз это же устройство придёт под другим. "
          + "Наблюдения с таким адресом не склеиваются."
        : IdentifiedByIpOnly
            ? "Средне: аппаратный адрес не получен, устройство опознано только по IP-адресу, "
              + "а IP в сети может достаться другому устройству."
            : "Надёжно: адрес выдан заводом и закреплён за устройством.";
}
