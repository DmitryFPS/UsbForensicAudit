using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace UsbForensicAudit;

/// <summary>
/// Сетевые связи из журналов Windows: подключения к Wi-Fi и к сетям вообще,
/// обращения к сетевым папкам, сеансы удалённого стола, наборы номера и туннели
/// VPN.
///
/// Реестр говорит, когда сеть видели впервые и в последний раз; журналы говорят,
/// сколько раз и как долго. Разница важна: по реестру нельзя отличить одно
/// подключение от сотни, а по журналу видно каждое — пока событие из него не
/// вытеснено. Поэтому рядом с найденным всегда идёт состояние канала: пустой
/// журнал и журнал без событий означают разное.
/// </summary>
internal sealed class NetworkEventLogCollector : INetworkArtifactCollector
{
    private const string WlanChannel = "Microsoft-Windows-WLAN-AutoConfig/Operational";
    private const string ProfileChannel = "Microsoft-Windows-NetworkProfile/Operational";
    private const string SmbConnectivityChannel = "Microsoft-Windows-SmbClient/Connectivity";
    private const string SmbOperationalChannel = "Microsoft-Windows-SMBClient/Operational";
    private const string SmbSecurityChannel = "Microsoft-Windows-SmbClient/Security";
    private const string RdpClientChannel = "Microsoft-Windows-TerminalServices-RDPClient/Operational";
    private const string RdpServerChannel =
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
    private const string VpnChannel = "Microsoft-Windows-VPN/Operational";
    private const string MobileChannel = "Microsoft-Windows-WWAN-SVC-EVENTS/Operational";
    private const string ApplicationChannel = "Application";

    /// <summary>
    /// Каналы, состояние которых нужно отчёту, даже когда событий в них нет:
    /// по ним видно, охватывает ли проверка Bluetooth, мобильный интернет и
    /// удалённый стол вообще.
    /// </summary>
    private static readonly string[] HealthChannels =
    [
        WlanChannel, ProfileChannel, SmbConnectivityChannel, SmbOperationalChannel, SmbSecurityChannel,
        RdpClientChannel, RdpServerChannel, VpnChannel, MobileChannel, ApplicationChannel,
        "Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational",
        "Microsoft-Windows-Bluetooth-MTPEnum/Operational",
        "Microsoft-Windows-Bluetooth-Policy/Operational",
        "Microsoft-Windows-DHCP-Client/Operational"
    ];

    private readonly int _maxPerChannel;

    public NetworkEventLogCollector()
        : this(5000)
    {
    }

    internal NetworkEventLogCollector(int maxPerChannel)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxPerChannel, 1);
        _maxPerChannel = maxPerChannel;
    }

    public string ProgressMessage => "Чтение журналов о сетевых подключениях...";

    public bool ShouldRun => true;

    public NetworkArtifactSet Collect(List<string> warnings)
    {
        var evidence = ReadChannelHealth(warnings);
        var index = NetworkProfileIndex.Build();

        var wireless = ReadWireless(warnings);
        var profiles = ReadNetworkProfiles(index, wireless, evidence, warnings);
        var shares = ReadFileShares(warnings);
        var desktops = ReadRemoteDesktop(warnings);
        var dialUp = ReadDialUp(warnings);

        var connections = new List<NetworkConnectionRecord>();
        connections.AddRange(wireless);
        connections.AddRange(profiles);
        connections.AddRange(shares);
        connections.AddRange(desktops);
        connections.AddRange(dialUp);

        return new NetworkArtifactSet(connections, evidence);
    }

    /// <summary>Состояние каналов записями доказательств и предупреждениями.</summary>
    private static List<EvidenceRecord> ReadChannelHealth(List<string> warnings)
    {
        var records = new List<EvidenceRecord>();
        foreach (var state in EventLogCollector.ReadChannelStates(HealthChannels))
        {
            records.Add(EventLogCollector.ToEvidence(state));
            if (!state.Exists || !state.IsEnabled || !string.IsNullOrEmpty(state.Error))
            {
                warnings.Add(state.Describe());
            }
        }

        return records;
    }

    // -------------------------------------------------------------- Wi-Fi

    /// <summary>
    /// Подключения к Wi-Fi. Здесь же способ защиты сети на момент подключения:
    /// сохранённый профиль показывает только текущую настройку, а событие — ту,
    /// с которой соединение состоялось.
    /// </summary>
    private List<NetworkConnectionRecord> ReadWireless(List<string> warnings)
    {
        var buckets = new Dictionary<string, Bucket>(StringComparer.OrdinalIgnoreCase);
        const string source = "Журнал Windows — подключения Wi-Fi";

        foreach (var item in Read(WlanChannel, "Microsoft-Windows-WLAN-AutoConfig", [8001, 8002, 8003, 11004], warnings))
        {
            var parsed = item.Parsed;
            var name = Field(parsed, "ProfileName", "SSID");
            if (name.Length == 0)
            {
                continue;
            }

            var bucket = Bucket.For(buckets, NetworkConnectionKind.WiFi, name, () => new NetworkConnectionRecord
            {
                Kind = NetworkConnectionKind.WiFi,
                Name = name,
                Source = source,
                Provenance = WlanChannel
            });

            var record = bucket.Record;
            record.Adapter = FirstNotEmpty(record.Adapter, Field(parsed, "InterfaceDescription", "Adapter"));

            if (parsed.EventId == 11004)
            {
                // Событие называет MAC самой машины, а не точки доступа: с ним
                // видно, каким адаптером пользовались, если их несколько.
                var mac = Field(parsed, "LocalMac");
                if (mac.Length > 0)
                {
                    bucket.AddDetail($"MAC адаптера этой машины: {mac}");
                }

                continue;
            }

            if (parsed.EventId == 8001)
            {
                record.Security = FirstNotEmpty(record.Security, DescribeWirelessSecurity(parsed));
                var phy = Field(parsed, "PHYType");
                if (phy.Length > 0)
                {
                    bucket.AddDetailOnce("стандарт связи", $"стандарт связи {phy}");
                }
            }

            bucket.Events.Add(new NetworkSessionEvent(
                parsed.TimestampUtc,
                parsed.EventId switch
                {
                    8001 => NetworkSessionRole.Start,
                    8003 => NetworkSessionRole.End,
                    _ => NetworkSessionRole.Failure
                },
                parsed.EventId switch
                {
                    // Способ подключения стоит рядом с самим подключением, а не в
                    // общем пояснении к сети: подключались к одной и той же сети
                    // то вручную, то автоматически, и в пояснении эти способы
                    // складывались друг за другом в бессмысленный перечень.
                    8001 => Combine("Подключение к сети Wi-Fi установлено", Field(parsed, "ConnectionMode")),
                    8003 => "Сеть Wi-Fi отключена",
                    _ => "Подключиться к сети Wi-Fi не удалось"
                },
                Field(parsed, "FailureReason", "Reason"),
                Source: source,
                Provenance: $"{WlanChannel}, событие {parsed.EventId}, запись {parsed.RecordId}"));
        }

        return Finish(buckets.Values, source, WlanChannel);
    }

    private static string DescribeWirelessSecurity(ParsedEventLogRecord parsed)
    {
        var authentication = Field(parsed, "AuthenticationAlgorithm");
        var cipher = Field(parsed, "CipherAlgorithm");
        if (authentication.Length == 0 && cipher.Length == 0)
        {
            return "";
        }

        var parts = new List<string>();
        if (authentication.Length > 0)
        {
            parts.Add($"проверка подлинности {authentication}");
        }

        if (cipher.Length > 0)
        {
            parts.Add($"шифрование {cipher}");
        }

        return string.Join(", ", parts);
    }

    // ------------------------------------------------------- Сети вообще

    /// <summary>
    /// Подключения к сети любого вида. Канал не различает Wi-Fi и провод, вид
    /// связи берётся из реестра по GUID профиля.
    ///
    /// Для сетей Wi-Fi, о которых уже рассказал журнал WLAN, эти события
    /// пропускаются: они описывают то же самое подключение с точностью до
    /// секунд, и в списке сеансов каждое соединение выглядело бы двумя.
    /// </summary>
    private List<NetworkConnectionRecord> ReadNetworkProfiles(
        NetworkProfileIndex index,
        IEnumerable<NetworkConnectionRecord> wireless,
        List<EvidenceRecord> evidence,
        List<string> warnings)
    {
        var covered = wireless
            .Where(x => x.Sessions.Count > 0)
            .Select(x => x.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var buckets = new Dictionary<string, Bucket>(StringComparer.OrdinalIgnoreCase);
        const string source = "Журнал Windows — подключения к сетям";
        var placeholders = new List<DateTimeOffset>();

        foreach (var item in Read(ProfileChannel, "Microsoft-Windows-NetworkProfile", [10000, 10001], warnings))
        {
            var parsed = item.Parsed;
            var name = Field(parsed, "Name", "Description");
            if (name.Length == 0)
            {
                continue;
            }

            if (NetworkTarget.IsPlaceholderName(name))
            {
                placeholders.Add(parsed.TimestampUtc);
                continue;
            }

            var kind = index.ResolveKind(Field(parsed, "Guid"), name);
            if (kind == NetworkConnectionKind.WiFi && covered.Contains(name))
            {
                continue;
            }

            var bucket = Bucket.For(buckets, kind, name, () => new NetworkConnectionRecord
            {
                Kind = kind,
                Name = name,
                Source = source,
                Provenance = ProfileChannel,
                Details = kind == NetworkConnectionKind.Unknown
                    ? "Вид связи по этой сети определить не удалось: профиля этой сети в реестре уже "
                      + "нет, а само событие вида связи не называет"
                    : ""
            });

            bucket.Events.Add(new NetworkSessionEvent(
                parsed.TimestampUtc,
                parsed.EventId == 10000 ? NetworkSessionRole.Start : NetworkSessionRole.End,
                DescribeNetworkEntry(kind, parsed.EventId == 10000),
                Source: source,
                Provenance: $"{ProfileChannel}, событие {parsed.EventId}, запись {parsed.RecordId}"));
        }

        if (placeholders.Count > 0)
        {
            evidence.Add(DescribePlaceholders(placeholders));
        }

        return Finish(buckets.Values, source, ProfileChannel);
    }

    /// <summary>
    /// Одно и то же событие для разных видов связи означает разное: для туннеля
    /// VPN это его подъём, для провода — включение кабеля в сеть.
    /// </summary>
    private static string DescribeNetworkEntry(string kind, bool entered) => (kind, entered) switch
    {
        (NetworkConnectionKind.Vpn, true) => "Туннель VPN поднят",
        (NetworkConnectionKind.Vpn, false) => "Туннель VPN разорван",
        (NetworkConnectionKind.WiFi, true) => "Машина вошла в сеть Wi-Fi",
        (NetworkConnectionKind.WiFi, false) => "Машина вышла из сети Wi-Fi",
        (NetworkConnectionKind.Wired, true) => "Машина вошла в проводную сеть",
        (NetworkConnectionKind.Wired, false) => "Машина вышла из проводной сети",
        (NetworkConnectionKind.MobileBroadband, true) => "Машина вошла в сеть мобильного интернета",
        (NetworkConnectionKind.MobileBroadband, false) => "Машина вышла из сети мобильного интернета",
        (_, true) => "Машина вошла в сеть",
        _ => "Машина вышла из сети"
    };

    /// <summary>
    /// События с именем-заглушкой не пропадают бесследно: по ним видно, сколько
    /// раз сеть менялась, — но какая это была сеть, они не говорят.
    /// </summary>
    private static EvidenceRecord DescribePlaceholders(List<DateTimeOffset> moments) => new()
    {
        TimestampUtc = moments.Max(),
        Source = "Журнал Windows — подключения к сетям",
        Provider = "Microsoft-Windows-NetworkProfile",
        Channel = ProfileChannel,
        EvidenceCategory = "Смена сети без имени",
        EvidenceStrength = "Context",
        Confidence = "High",
        CanEstablishConnectionDate = false,
        Summary = $"Событий входа в сеть без её имени: {moments.Count}. "
                  + $"Первое — {DateDisplay.FormatMoscow(moments.Min())}, "
                  + $"последнее — {DateDisplay.FormatMoscow(moments.Max())}.",
        UserExplanation = "Пока Windows определяет, куда попала машина, сеть называется "
                          + "«Идентификация...», а если определить не удалось — «Неопознанная сеть». "
                          + "Это состояние, а не сеть: за одним таким именем в разное время стоят "
                          + "разные сети. Отдельной строкой в списке связей они не показаны, иначе "
                          + "получилась бы сеть, к которой подключались сотни раз. Сами события "
                          + "означают, что связь в эти моменты переключалась.",
        Provenance = $"{ProfileChannel}, события 10000 и 10001 с именем-заглушкой"
    };

    // ------------------------------------------------------ Сетевые папки

    /// <summary>
    /// Обращения к сетевым папкам: к какому серверу и к какому ресурсу на нём.
    /// Именно здесь видно, куда с этой машины могли уйти файлы.
    ///
    /// Имя сервера Windows пишет по-разному: «\20.20.20.76», «\20.20.20.76\r0»
    /// и — вместо сервера — имя сетевого устройства «\Device\NetBT_Tcpip_{…}».
    /// Последнее сервером не является и отбрасывается, иначе в списке появились
    /// бы «серверы» с именами драйверов.
    /// </summary>
    private List<NetworkConnectionRecord> ReadFileShares(List<string> warnings)
    {
        var buckets = new Dictionary<string, Bucket>(StringComparer.OrdinalIgnoreCase);
        const string source = "Журнал Windows — обращения к сетевым папкам";
        var channels = new[] { SmbConnectivityChannel, SmbOperationalChannel, SmbSecurityChannel };
        var points = new Dictionary<string, List<PointEvent>>(StringComparer.OrdinalIgnoreCase);

        foreach (var channel in channels)
        {
            foreach (var item in Read(channel, "Microsoft-Windows-SMBClient", [], warnings))
            {
                var parsed = item.Parsed;
                if (!NetworkTarget.TryReadServer(Field(parsed, "ServerName", "Server"), out var host, out var share))
                {
                    continue;
                }

                var bucket = Bucket.For(buckets, NetworkConnectionKind.NetworkShare, host,
                    () => new NetworkConnectionRecord
                    {
                        Kind = NetworkConnectionKind.NetworkShare,
                        Name = host,
                        Direction = NetworkDirection.Outgoing,
                        Source = source,
                        Details = NetworkConnectionExplanations.ShareServer,
                        Provenance = channel
                    });

                if (NetworkEventValues.TryReadSocketAddress(Field(parsed, "RemoteAddress"), out var address, out _)
                    && !NetworkTarget.IsLoopback(address))
                {
                    bucket.Record.Address = FirstNotEmpty(bucket.Record.Address, address);
                }

                if (share.Length > 0)
                {
                    bucket.AddVisit(new NetworkVisit
                    {
                        WhenUtc = parsed.TimestampUtc,
                        Kind = NetworkTarget.IsAdministrativeShare(share)
                            ? NetworkVisitKind.Host
                            : NetworkVisitKind.Folder,
                        Target = $@"\\{host}\{share}",
                        Title = NetworkTarget.IsAdministrativeShare(share)
                            ? "Служебный ресурс Windows, а не папка с файлами: через него идут "
                              + "запросы управления и проверка доступа"
                            : "",
                        Source = source,
                        TimeMeaning = "Время события журнала: когда к ресурсу обращались",
                        Provenance = $"{channel}, событие {parsed.EventId}, запись {parsed.RecordId}"
                    });
                }

                AddPoint(points, host, new PointEvent(
                    parsed.TimestampUtc,
                    DescribeShareOutcome(item.Description, parsed),
                    NetworkEventValues.DescribeStatus(Field(parsed, "Status")),
                    $"{channel}, событие {parsed.EventId}"));
            }
        }

        foreach (var bucket in buckets.Values)
        {
            if (points.TryGetValue(bucket.Record.Name, out var list))
            {
                bucket.Events.AddRange(AggregateByDay(list, source));
            }
        }

        return Finish(buckets.Values, source, SmbConnectivityChannel);
    }

    /// <summary>
    /// Что произошло, словами самой Windows: первая фраза описания события. Свои
    /// формулировки здесь были бы догадкой — событий у клиента SMB несколько
    /// десятков видов, и каждое означает своё.
    /// </summary>
    private static string DescribeShareOutcome(string description, ParsedEventLogRecord parsed)
    {
        var sentence = FirstLine(description);
        return sentence.Length > 0 ? sentence : $"Событие клиента сетевых папок {parsed.EventId}";
    }

    /// <summary>
    /// Однотипные обращения сводятся к одной строке за день. Иначе история к
    /// одному серверу — двести одинаковых строк за одну минуту повторного
    /// подключения, по которым ничего не прочитать.
    /// </summary>
    private static List<NetworkSessionEvent> AggregateByDay(List<PointEvent> points, string source)
    {
        return points
            .GroupBy(x => (Day: x.WhenUtc.UtcDateTime.Date, x.Outcome, x.Status))
            .Select(group =>
            {
                var first = group.OrderBy(x => x.WhenUtc).First();
                var count = group.Count();
                var reason = string.Join("; ", new[]
                {
                    group.Key.Status.Length > 0 ? $"итог операции: {group.Key.Status}" : "",
                    count > 1 ? $"таких же событий за этот день: {count}" : "",
                    $"источник: {first.Provenance}"
                }.Where(x => x.Length > 0));

                return new NetworkSessionEvent(
                    first.WhenUtc,
                    NetworkSessionRole.Failure,
                    group.Key.Outcome,
                    reason,
                    Source: source,
                    Provenance: first.Provenance);
            })
            .OrderByDescending(x => x.WhenUtc)
            .Take(300)
            .ToList();
    }

    // ---------------------------------------------------- Удалённый стол

    /// <summary>
    /// Удалённый стол в обе стороны: куда подключались с этой машины и кто
    /// подключался к ней. Направление здесь принципиально: первое — работа
    /// пользователя, второе — доступ извне.
    /// </summary>
    private List<NetworkConnectionRecord> ReadRemoteDesktop(List<string> warnings)
    {
        var buckets = new Dictionary<string, Bucket>(StringComparer.OrdinalIgnoreCase);
        const string outgoing = "Журнал Windows — исходящие подключения удалённого стола";
        const string incoming = "Журнал Windows — входящие подключения удалённого стола";

        foreach (var item in Read(RdpClientChannel, "Microsoft-Windows-TerminalServices-ClientActiveXCore",
                     [1024, 1026, 1102, 1105], warnings))
        {
            var parsed = item.Parsed;
            var host = ExtractHost(parsed);
            if (host.Length == 0)
            {
                continue;
            }

            var bucket = Bucket.For(buckets, NetworkConnectionKind.RemoteDesktop, host,
                () => new NetworkConnectionRecord
                {
                    Kind = NetworkConnectionKind.RemoteDesktop,
                    Name = host,
                    Direction = NetworkDirection.Outgoing,
                    Source = outgoing,
                    Details = NetworkConnectionExplanations.RemoteDesktopOutgoing,
                    Provenance = RdpClientChannel
                });

            bucket.Events.Add(new NetworkSessionEvent(
                parsed.TimestampUtc,
                parsed.EventId == 1024 ? NetworkSessionRole.Start : NetworkSessionRole.End,
                FirstLine(item.Description) is { Length: > 0 } text
                    ? text
                    : $"Событие удалённого стола {parsed.EventId}",
                Source: outgoing,
                Provenance: $"{RdpClientChannel}, событие {parsed.EventId}, запись {parsed.RecordId}"));
        }

        foreach (var item in Read(RdpServerChannel, "Microsoft-Windows-TerminalServices-LocalSessionManager",
                     [21, 24, 25], warnings))
        {
            var parsed = item.Parsed;

            // Вход с самой машины эта служба тоже записывает, подставляя в поле
            // адреса слово «ЛОКАЛЬНЫЙ». Такой вход к сети отношения не имеет, и
            // считать его подключением извне нельзя.
            var host = Field(parsed, "Address", "ClientAddress");
            if (!NetworkTarget.LooksLikeHost(host) || NetworkTarget.IsLoopback(host))
            {
                continue;
            }

            var bucket = Bucket.For(buckets, NetworkConnectionKind.RemoteDesktop, host,
                () => new NetworkConnectionRecord
                {
                    Kind = NetworkConnectionKind.RemoteDesktop,
                    Name = host,
                    Direction = NetworkDirection.Incoming,
                    Source = incoming,
                    Details = NetworkConnectionExplanations.RemoteDesktopIncoming,
                    Provenance = RdpServerChannel
                });

            bucket.Record.Account = FirstNotEmpty(bucket.Record.Account, Field(parsed, "User"));

            bucket.Events.Add(new NetworkSessionEvent(
                parsed.TimestampUtc,
                parsed.EventId == 24 ? NetworkSessionRole.End : NetworkSessionRole.Start,
                parsed.EventId switch
                {
                    21 => "Вход на эту машину по удалённому столу",
                    25 => "Возврат к сеансу удалённого стола на этой машине",
                    _ => "Сеанс удалённого стола на этой машине завершён"
                },
                Account: Field(parsed, "User"),
                Source: incoming,
                Provenance: $"{RdpServerChannel}, событие {parsed.EventId}, запись {parsed.RecordId}"));
        }

        return Finish(buckets.Values, outgoing, RdpClientChannel);
    }

    // -------------------------------------------------------------- VPN

    /// <summary>
    /// Наборы номера и туннели VPN из журнала приложений. Значения в этих
    /// событиях не подписаны именами, поэтому имя подключения и адрес сервера
    /// определяются по виду значения, а итог берётся словами самой Windows.
    /// </summary>
    private List<NetworkConnectionRecord> ReadDialUp(List<string> warnings)
    {
        var buckets = new Dictionary<string, Bucket>(StringComparer.OrdinalIgnoreCase);
        const string source = "Журнал Windows — подключения VPN и набор номера";

        foreach (var item in Read(ApplicationChannel, "RasClient", [], warnings))
        {
            var values = ReadPositionalValues(item.Parsed.RawXml);
            var account = values.FirstOrDefault(x => x.Contains('\\') && !x.Contains(' ')) ?? "";
            var name = values.FirstOrDefault(x =>
                x != account && x.Length is > 0 and <= 120 && !IsNumber(x) && !NetworkTarget.LooksLikeHost(x)) ?? "";
            var address = values.FirstOrDefault(x => x != account && x != name && NetworkTarget.LooksLikeHost(x)) ?? "";
            var title = FirstNotEmpty(name, address);
            if (title.Length == 0)
            {
                continue;
            }

            var bucket = Bucket.For(buckets, NetworkConnectionKind.Vpn, title, () => new NetworkConnectionRecord
            {
                Kind = NetworkConnectionKind.Vpn,
                Name = title,
                Address = address,
                Account = account,
                Direction = NetworkDirection.Outgoing,
                Source = source,
                Provenance = $"{ApplicationChannel}, источник RasClient"
            });

            bucket.Record.Address = FirstNotEmpty(bucket.Record.Address, address);

            bucket.Events.Add(new NetworkSessionEvent(
                item.Parsed.TimestampUtc,
                item.Parsed.EventId switch
                {
                    20221 or 20222 or 20223 => NetworkSessionRole.Start,
                    20226 => NetworkSessionRole.End,
                    _ => NetworkSessionRole.Failure
                },
                FirstLine(item.Description) is { Length: > 0 } text
                    ? text
                    : $"Событие подключения RasClient {item.Parsed.EventId}",
                Account: account,
                Source: source,
                Provenance: $"{ApplicationChannel}, RasClient, событие {item.Parsed.EventId}, "
                            + $"запись {item.Parsed.RecordId}"));
        }

        return Finish(buckets.Values, source, ApplicationChannel);
    }

    // ---------------------------------------------------------- Служебное

    private sealed record PointEvent(
        DateTimeOffset WhenUtc,
        string Outcome,
        string Status,
        string Provenance);

    private sealed class Bucket
    {
        private readonly List<string> _details = [];

        private Bucket(NetworkConnectionRecord record)
        {
            Record = record;
            if (record.Details.Length > 0)
            {
                _details.Add(record.Details);
            }
        }

        public NetworkConnectionRecord Record { get; }

        public List<NetworkSessionEvent> Events { get; } = [];

        public Dictionary<string, NetworkVisit> Visits { get; } = new(StringComparer.OrdinalIgnoreCase);

        public static Bucket For(
            Dictionary<string, Bucket> buckets,
            string kind,
            string name,
            Func<NetworkConnectionRecord> create)
        {
            var key = $"{kind}|{name}";
            if (!buckets.TryGetValue(key, out var bucket))
            {
                bucket = new Bucket(create());
                buckets[key] = bucket;
            }

            return bucket;
        }

        public void AddDetail(string text)
        {
            if (text.Length > 0 && !_details.Contains(text, StringComparer.OrdinalIgnoreCase))
            {
                _details.Add(text);
            }
        }

        /// <summary>
        /// Пояснение, которого достаточно одного: стандарт связи у сети мог
        /// меняться от подключения к подключению, но перечень «802.11ac,
        /// 802.11n, 802.11ax» в пояснении к сети ничего читателю не даёт.
        /// </summary>
        public void AddDetailOnce(string prefix, string text)
        {
            if (!_details.Any(x => x.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
            {
                AddDetail(text);
            }
        }

        /// <summary>
        /// Одна и та же папка открывалась много раз: в списке она остаётся одной
        /// строкой с самым поздним временем и числом обращений.
        /// </summary>
        public void AddVisit(NetworkVisit visit)
        {
            if (!Visits.TryGetValue(visit.Target, out var existing))
            {
                visit.MentionCount = 1;
                Visits[visit.Target] = visit;
                return;
            }

            existing.MentionCount = (existing.MentionCount ?? 1) + 1;
            if (visit.WhenUtc > existing.WhenUtc)
            {
                existing.WhenUtc = visit.WhenUtc;
                existing.Provenance = visit.Provenance;
            }
        }

        public void Apply()
        {
            Record.Details = string.Join("; ", _details.Where(x => x.Length > 0));
        }
    }

    private static List<NetworkConnectionRecord> Finish(
        IEnumerable<Bucket> buckets,
        string source,
        string channel)
    {
        var result = new List<NetworkConnectionRecord>();
        foreach (var bucket in buckets)
        {
            bucket.Apply();
            var record = bucket.Record;
            record.Sessions.AddRange(NetworkSessionPairing.Pair(bucket.Events));
            record.Visits.AddRange(bucket.Visits.Values
                .OrderByDescending(x => x.WhenUtc ?? DateTimeOffset.MinValue));

            var moments = bucket.Events.Select(x => x.WhenUtc).ToList();
            if (moments.Count > 0)
            {
                record.FirstSeenUtc = moments.Min();
                record.LastSeenUtc = moments.Max();
                record.FirstSeenProvenance = $"самое раннее сохранившееся событие в журнале {channel}";
                record.LastSeenProvenance = $"самое позднее событие в журнале {channel}";
            }

            record.Source = FirstNotEmpty(record.Source, source);
            result.Add(record);
        }

        return result;
    }

    private sealed record ReadItem(ParsedEventLogRecord Parsed, string Description);

    private List<ReadItem> Read(
        string channel,
        string provider,
        int[] eventIds,
        ICollection<string> warnings)
    {
        var items = new List<ReadItem>();
        try
        {
            var query = new EventLogQuery(channel, PathType.LogName, BuildXPath(provider, eventIds))
            {
                ReverseDirection = true
            };

            using var reader = new EventLogReader(query);
            var scanned = 0;
            while (scanned < _maxPerChannel)
            {
                using var record = reader.ReadEvent();
                if (record is null)
                {
                    return items;
                }

                scanned++;
                if (EventLogRecordParser.TryParse(SafeXml(record), out var parsed) && parsed is not null)
                {
                    items.Add(new ReadItem(parsed, SafeFormat(record)));
                }
            }

            EventLogRetentionPolicy.AddCapWarning(warnings, $"{channel} ({provider})", _maxPerChannel);
        }
        catch (EventLogNotFoundException)
        {
            // Канал есть не в каждой сборке Windows. Его отсутствие уже
            // записано состоянием каналов и повторного предупреждения не требует.
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Журнал {channel} ({provider}) недоступен: {exception.Message}");
        }

        return items;
    }

    private static string BuildXPath(string provider, int[] eventIds)
    {
        var providerClause = $"Provider[@Name='{provider}']";
        if (eventIds.Length == 0)
        {
            return $"*[System[{providerClause}]]";
        }

        var ids = string.Join(" or ", eventIds.Select(id => $"EventID={id}"));
        return $"*[System[{providerClause} and ({ids})]]";
    }

    private static string SafeXml(EventRecord record)
    {
        try
        {
            return record.ToXml();
        }
        catch
        {
            return "";
        }
    }

    private static string SafeFormat(EventRecord record)
    {
        try
        {
            return record.FormatDescription() ?? "";
        }
        catch
        {
            return "";
        }
    }

    private static string Field(ParsedEventLogRecord parsed, params string[] names)
    {
        foreach (var name in names)
        {
            if (parsed.Fields.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return "";
    }

    /// <summary>
    /// Узел из события, которое не подписывает поле с адресом одним и тем же
    /// именем: у клиента удалённого стола это «Name» или «Value», у службы
    /// сеансов — «Адрес сетевого клиента: 10.0.0.5» внутри строки описания.
    /// </summary>
    private static string ExtractHost(ParsedEventLogRecord parsed)
    {
        foreach (var name in new[] { "Name", "ServerName", "Server", "Address", "ClientAddress", "Value" })
        {
            var direct = Field(parsed, name);
            if (NetworkTarget.LooksLikeHost(direct))
            {
                return direct;
            }
        }

        foreach (var value in parsed.Fields.Values)
        {
            foreach (var token in value.Split([' ', ',', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                var candidate = token.Trim('[', ']', '.', ':', ';', '(', ')');

                // Проверка на адрес без точки бесполезна: номер сеанса «1»
                // System.Net.IPAddress разбирает как адрес 0.0.0.1, и номер
                // сеанса становился «узлом, к которому подключались».
                if (candidate.Contains('.')
                    && System.Net.IPAddress.TryParse(candidate, out _))
                {
                    return candidate;
                }
            }
        }

        return "";
    }

    /// <summary>
    /// Значения события, у которых нет имени поля. Так пишет RasClient: смысл
    /// значения задаётся только его местом в списке.
    /// </summary>
    private static List<string> ReadPositionalValues(string xml)
    {
        try
        {
            var root = XDocument.Parse(xml).Root;
            if (root is null)
            {
                return [];
            }

            return
            [
                .. root.Descendants()
                    .Where(x => x.Name.LocalName == "Data" && !x.HasElements)
                    .Select(x => x.Value.Trim())
                    .Where(x => x.Length > 0)
            ];
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Первая строка описания события — то, что Windows считает главным. По
    /// точке эту строку резать нельзя: «Соединение разорвано, т. к. сервер не
    /// ответил» обрывалось на «Соединение разорвано, т».
    /// </summary>
    private static string FirstLine(string text)
    {
        var line = (text ?? "")
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault()?
            .Trim() ?? "";

        return line.Length > 220 ? line[..220].TrimEnd() + "…" : line;
    }

    /// <summary>Итог и уточнение к нему одной строкой.</summary>
    private static string Combine(string text, string addition) =>
        addition.Length > 0 ? $"{text}; способ подключения: {addition}" : text;

    private static void AddPoint(
        Dictionary<string, List<PointEvent>> points,
        string host,
        PointEvent point)
    {
        if (!points.TryGetValue(host, out var list))
        {
            list = [];
            points[host] = list;
        }

        list.Add(point);
    }

    private static int? ReadNumber(string value) =>
        int.TryParse(value, out var parsed) ? parsed : null;

    private static bool IsNumber(string value) => value.All(char.IsAsciiDigit);

    private static string FirstNotEmpty(params string[] values) =>
        values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "";
}
