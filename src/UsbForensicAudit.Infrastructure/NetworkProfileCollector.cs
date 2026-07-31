using System.IO;
using Microsoft.Win32;

namespace UsbForensicAudit;

/// <summary>
/// Сети, к которым машина подключалась: Wi-Fi, провод, туннели VPN, мобильный
/// интернет.
///
/// Основной источник — список сетей в реестре: он хранит имя сети, дату первого
/// и последнего подключения и тип интерфейса. Подписи сетей добавляют MAC шлюза,
/// по которому две сети с одинаковым именем различаются. Сохранённые профили
/// Wi-Fi добавляют способ защиты. Параметры интерфейсов добавляют адреса, которые
/// машина получала в этой сети.
/// </summary>
internal sealed class NetworkProfileCollector : INetworkArtifactCollector
{
    private const string ProfilesPath =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles";

    private const string SignaturesPath =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures";

    private const string InterfacesPath =
        @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

    private const string AdaptersPath =
        @"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

    private const string WlanProfilesPath =
        @"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces";

    private const string SourceName = "Реестр Windows — список сетей";

    public string ProgressMessage => "Чтение списка сетей: Wi-Fi, провод, VPN...";

    public bool ShouldRun => true;

    public NetworkArtifactSet Collect(List<string> warnings)
    {
        var signatures = ReadSignatures(warnings);
        var adapters = ReadAdapters(warnings);
        var wlanProfiles = ReadWlanProfiles(warnings);
        var interfaces = ReadInterfaces(warnings);
        var connections = ReadProfiles(signatures, wlanProfiles, warnings);

        AttachAddresses(connections, interfaces, adapters, signatures);

        return new NetworkArtifactSet(connections, DescribeUnmatchedInterfaces(interfaces, adapters));
    }

    private static List<NetworkConnectionRecord> ReadProfiles(
        Dictionary<string, NetworkSignature> signatures,
        Dictionary<string, WlanProfileInfo> wlanProfiles,
        List<string> warnings)
    {
        var connections = new List<NetworkConnectionRecord>();
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(ProfilesPath);
            if (root is null)
            {
                warnings.Add($"Источник недоступен или отсутствует: HKLM\\{ProfilesPath}. "
                             + "Список сетей, к которым подключалась машина, прочитать не удалось.");
                return connections;
            }

            foreach (var guid in root.GetSubKeyNames())
            {
                using var key = root.OpenSubKey(guid);
                if (key is null)
                {
                    continue;
                }

                var name = ReadString(key, "ProfileName");
                var description = ReadString(key, "Description");
                if (name.Length == 0 && description.Length == 0)
                {
                    continue;
                }

                var nameType = ReadInt(key, "NameType") ?? 0;
                var (kind, typeExplanation) = NetworkListParsers.DescribeNameType(nameType);
                signatures.TryGetValue(guid, out var signature);
                wlanProfiles.TryGetValue(name.Length > 0 ? name : description, out var wlan);

                var record = new NetworkConnectionRecord
                {
                    Kind = kind,
                    Name = name.Length > 0 ? name : description,
                    FirstSeenUtc = NetworkListParsers.TryReadSystemTime(key.GetValue("DateCreated") as byte[]),
                    LastSeenUtc = NetworkListParsers.TryReadSystemTime(key.GetValue("DateLastConnected") as byte[]),
                    FirstSeenProvenance = $@"DateCreated в HKLM\{ProfilesPath}\{guid}; "
                                          + "значение записано в местном времени машины и приведено к UTC",
                    LastSeenProvenance = $@"DateLastConnected в HKLM\{ProfilesPath}\{guid}; "
                                         + "значение записано в местном времени машины и приведено к UTC",
                    Security = wlan?.SecurityText ?? "",
                    Source = SourceName,
                    Provenance = $@"HKLM\{ProfilesPath}\{guid}",
                    Details = BuildDetails(kind, typeExplanation, description, name,
                        ReadInt(key, "Category"), signature, wlan)
                };

                connections.Add(record);
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Ошибка чтения HKLM\\{ProfilesPath}: {exception.Message}");
        }

        return connections;
    }

    /// <summary>
    /// Пояснение к строке: чем эта запись является и что о ней известно кроме
    /// имени. Здесь же называется случай, когда сохранённого профиля Wi-Fi нет:
    /// сеть в списке осталась, а профиль удалён — это отдельный факт.
    /// </summary>
    private static string BuildDetails(
        string kind,
        string typeExplanation,
        string description,
        string profileName,
        int? category,
        NetworkSignature? signature,
        WlanProfileInfo? wlan)
    {
        var parts = new List<string> { typeExplanation };

        var categoryText = NetworkListParsers.DescribeCategory(category);
        if (categoryText.Length > 0)
        {
            parts.Add($"Категория в Windows: {categoryText}.");
        }

        if (description.Length > 0 && !description.Equals(profileName, StringComparison.OrdinalIgnoreCase))
        {
            parts.Add($"Имя сети, которое сообщала точка доступа: {description}.");
        }

        if (signature is not null)
        {
            if (signature.GatewayMac.Length > 0)
            {
                parts.Add($"MAC шлюза: {signature.GatewayMac} — по нему различаются разные сети "
                          + "с одинаковым именем.");
            }

            if (signature.DnsSuffix.Length > 0)
            {
                parts.Add($"Домен сети: {signature.DnsSuffix}.");
            }
        }

        if (wlan is not null)
        {
            if (wlan.ConnectionMode.Length > 0)
            {
                parts.Add($"Сохранённый профиль Wi-Fi есть, сеть {wlan.ConnectionMode}.");
            }

            if (wlan.HasStoredKey)
            {
                parts.Add("Пароль сети сохранён и зашифрован на ключе этой машины; "
                          + "аудит его не раскрывает.");
            }
        }
        else if (kind == NetworkConnectionKind.WiFi)
        {
            parts.Add("Сохранённого профиля Wi-Fi с таким именем нет: его либо удалили после "
                      + "подключения, либо сеть добавляли под другой учётной записью. "
                      + "Сама запись о подключении при удалении профиля не исчезает.");
        }

        return string.Join(" ", parts.Where(x => x.Length > 0));
    }

    /// <summary>
    /// Подписи сетей: MAC шлюза и домен. Ключ подписи — хеш, поэтому связь с
    /// профилем идёт через ProfileGuid внутри значения.
    /// </summary>
    private static Dictionary<string, NetworkSignature> ReadSignatures(List<string> warnings)
    {
        var signatures = new Dictionary<string, NetworkSignature>(StringComparer.OrdinalIgnoreCase);
        foreach (var scope in new[] { "Unmanaged", "Managed" })
        {
            var path = $@"{SignaturesPath}\{scope}";
            try
            {
                using var root = Registry.LocalMachine.OpenSubKey(path);
                if (root is null)
                {
                    continue;
                }

                foreach (var hash in root.GetSubKeyNames())
                {
                    using var key = root.OpenSubKey(hash);
                    if (key is null)
                    {
                        continue;
                    }

                    var profileGuid = ReadString(key, "ProfileGuid");
                    if (profileGuid.Length == 0)
                    {
                        continue;
                    }

                    signatures[profileGuid] = new NetworkSignature(
                        NetworkListParsers.FormatMac(key.GetValue("DefaultGatewayMac") as byte[]),
                        CleanSuffix(ReadString(key, "DnsSuffix")),
                        ReadString(key, "FirstNetwork"),
                        scope == "Managed");
                }
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                warnings.Add($"Ошибка чтения HKLM\\{path}: {exception.Message}");
            }
        }

        return signatures;
    }

    /// <summary>Windows пишет «отсутствует» словом, и это не имя домена.</summary>
    private static string CleanSuffix(string value) =>
        value.Contains("отсутств", StringComparison.OrdinalIgnoreCase)
        || value.Equals("<none>", StringComparison.OrdinalIgnoreCase)
            ? ""
            : value;

    /// <summary>
    /// Имена сетевых подключений, как их видит человек в панели управления:
    /// «Беспроводная сеть», «Ethernet», «SigmaVPN».
    /// </summary>
    private static Dictionary<string, NetworkAdapter> ReadAdapters(List<string> warnings)
    {
        var adapters = new Dictionary<string, NetworkAdapter>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(AdaptersPath);
            if (root is null)
            {
                return adapters;
            }

            foreach (var guid in root.GetSubKeyNames())
            {
                using var connection = root.OpenSubKey($@"{guid}\Connection");
                if (connection is null)
                {
                    continue;
                }

                var name = ReadString(connection, "Name");
                if (name.Length == 0)
                {
                    continue;
                }

                adapters[guid.Trim('{', '}')] = new NetworkAdapter(name, ReadInt(connection, "MediaSubType"));
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Ошибка чтения HKLM\\{AdaptersPath}: {exception.Message}");
        }

        return adapters;
    }

    private static Dictionary<string, WlanProfileInfo> ReadWlanProfiles(List<string> warnings)
    {
        var profiles = new Dictionary<string, WlanProfileInfo>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!Directory.Exists(WlanProfilesPath))
            {
                return profiles;
            }

            foreach (var file in Directory.EnumerateFiles(WlanProfilesPath, "*.xml",
                         SearchOption.AllDirectories).Take(2048))
            {
                var profile = NetworkListParsers.ParseWlanProfile(SafeReadText(file));
                if (profile is null)
                {
                    continue;
                }

                foreach (var key in new[] { profile.Name, profile.Ssid })
                {
                    if (key.Length > 0)
                    {
                        profiles[key] = profile;
                    }
                }
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Профили Wi-Fi в {WlanProfilesPath} прочитать не удалось: {exception.Message}. "
                         + "Способ защиты сетей в отчёте останется незаполненным.");
        }

        return profiles;
    }

    private static string SafeReadText(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (IOException)
        {
            return "";
        }
        catch (UnauthorizedAccessException)
        {
            return "";
        }
    }

    /// <summary>
    /// Адреса, которые машина получала: свой адрес, шлюз, DNS, сервер DHCP и
    /// срок аренды. Имя сети Wi-Fi лежит здесь же в подсказке DhcpNetworkHint.
    /// </summary>
    private static List<NetworkInterfaceAddresses> ReadInterfaces(List<string> warnings)
    {
        var interfaces = new List<NetworkInterfaceAddresses>();
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(InterfacesPath);
            if (root is null)
            {
                warnings.Add($"Источник недоступен или отсутствует: HKLM\\{InterfacesPath}. "
                             + "Адреса, которые машина получала в сетях, прочитать не удалось.");
                return interfaces;
            }

            foreach (var guid in root.GetSubKeyNames())
            {
                using var key = root.OpenSubKey(guid);
                if (key is null)
                {
                    continue;
                }

                var address = FirstNotEmpty(ReadString(key, "DhcpIPAddress"), ReadString(key, "IPAddress"));
                var nameServer = FirstNotEmpty(ReadString(key, "DhcpNameServer"), ReadString(key, "NameServer"));
                if (address.Length == 0 && nameServer.Length == 0)
                {
                    continue;
                }

                var (gatewayFromHardware, gatewayMac) =
                    NetworkListParsers.ReadGatewayHardware(key.GetValue("DhcpGatewayHardware") as byte[]);

                interfaces.Add(new NetworkInterfaceAddresses(
                    guid.Trim('{', '}'),
                    address,
                    FirstNotEmpty(ReadString(key, "DhcpDefaultGateway"), ReadString(key, "DefaultGateway"),
                        gatewayFromHardware),
                    gatewayMac,
                    nameServer,
                    ReadString(key, "DhcpServer"),
                    FirstNotEmpty(ReadString(key, "DhcpDomain"), ReadString(key, "Domain")),
                    NetworkListParsers.DecodeNetworkHint(ReadString(key, "DhcpNetworkHint")),
                    ReadUnixTime(key, "LeaseObtainedTime"),
                    ReadUnixTime(key, "LeaseTerminatesTime")));
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Ошибка чтения HKLM\\{InterfacesPath}: {exception.Message}");
        }

        return interfaces;
    }

    /// <summary>
    /// Привязывает адреса к сети. Признак берётся только надёжный: подсказка с
    /// именем сети Wi-Fi, совпадение имени подключения с именем профиля или MAC
    /// шлюза при совпадающем виде связи. Догадка здесь недопустима: приписать
    /// адрес проводного подключения сети Wi-Fi значит соврать о том, где машина
    /// находилась.
    /// </summary>
    private static void AttachAddresses(
        List<NetworkConnectionRecord> connections,
        List<NetworkInterfaceAddresses> interfaces,
        Dictionary<string, NetworkAdapter> adapters,
        Dictionary<string, NetworkSignature> signatures)
    {
        foreach (var item in interfaces)
        {
            adapters.TryGetValue(item.AdapterGuid, out var adapter);
            var match = FindConnection(connections, item, adapter, signatures);
            if (match is null)
            {
                continue;
            }

            item.MatchedTo = match.Name;
            foreach (var line in item.Describe(adapter?.Name ?? "", withAdapter: false))
            {
                if (!match.LocalAddresses.Contains(line))
                {
                    match.LocalAddresses.Add(line);
                }
            }

            if (adapter is not null && match.Adapter.Length == 0)
            {
                match.Adapter = adapter.Name;
            }
        }
    }

    private static NetworkConnectionRecord? FindConnection(
        List<NetworkConnectionRecord> connections,
        NetworkInterfaceAddresses item,
        NetworkAdapter? adapter,
        Dictionary<string, NetworkSignature> signatures)
    {
        if (item.WifiName.Length > 0)
        {
            var byName = connections.FirstOrDefault(x =>
                x.Kind == NetworkConnectionKind.WiFi
                && x.Name.Equals(item.WifiName, StringComparison.OrdinalIgnoreCase));
            if (byName is not null)
            {
                return byName;
            }
        }

        if (adapter is not null)
        {
            var byAdapter = connections.FirstOrDefault(x =>
                x.Name.Equals(adapter.Name, StringComparison.OrdinalIgnoreCase));
            if (byAdapter is not null)
            {
                return byAdapter;
            }
        }

        if (item.GatewayMac.Length == 0)
        {
            return null;
        }

        var expected = adapter?.IsWireless == true ? NetworkConnectionKind.WiFi : NetworkConnectionKind.Wired;
        return connections.FirstOrDefault(x =>
            x.Kind == expected
            && signatures.TryGetValue(GuidOf(x.Provenance), out var signature)
            && signature.GatewayMac.Equals(item.GatewayMac, StringComparison.OrdinalIgnoreCase));
    }

    private static string GuidOf(string provenance)
    {
        var start = provenance.LastIndexOf('{');
        return start < 0 ? "" : provenance[start..];
    }

    /// <summary>
    /// Адреса интерфейсов, которые не удалось отнести ни к одной сети, всё равно
    /// нужны отчёту: по ним видно, в каком сегменте находилась машина. Они идут
    /// записями доказательств, а не строками сетей, чтобы не выдумывать связь.
    /// </summary>
    private static List<EvidenceRecord> DescribeUnmatchedInterfaces(
        List<NetworkInterfaceAddresses> interfaces,
        Dictionary<string, NetworkAdapter> adapters)
    {
        var records = new List<EvidenceRecord>();
        foreach (var item in interfaces.Where(x => x.MatchedTo.Length == 0))
        {
            adapters.TryGetValue(item.AdapterGuid, out var adapter);
            var lines = item.Describe(adapter?.Name ?? "");
            if (lines.Count == 0)
            {
                continue;
            }

            records.Add(new EvidenceRecord
            {
                TimestampUtc = item.LeaseObtainedUtc ?? DateTimeOffset.UtcNow,
                Source = "Реестр Windows — адреса сетевых подключений",
                EvidenceCategory = "Адрес этой машины в сети",
                Summary = string.Join("; ", lines),
                UserExplanation = "Адреса, которые машина получала через это подключение. К конкретной "
                                  + "сети из списка они не отнесены: имени сети в параметрах подключения "
                                  + "нет, а MAC шлюза либо не совпал ни с одной записью, либо принадлежит "
                                  + "сети другого вида связи. Приписать адрес чужой сети значит соврать о "
                                  + "том, где машина находилась, поэтому связь не выдумывается.",
                Provenance = $@"HKLM\{InterfacesPath}\{{{item.AdapterGuid}}}",
                EvidenceStrength = "Direct",
                Confidence = "High"
            });
        }

        return records;
    }

    private static DateTimeOffset? ReadUnixTime(RegistryKey key, string valueName) =>
        ReadInt(key, valueName) is { } seconds and > 0
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;

    private static int? ReadInt(RegistryKey key, string valueName) =>
        key.GetValue(valueName) switch
        {
            int value => value,
            long value => (int)value,
            _ => null
        };

    private static string ReadString(RegistryKey key, string valueName) =>
        key.GetValue(valueName) switch
        {
            string value => value.Trim(),
            string[] values => string.Join("; ", values.Where(x => !string.IsNullOrWhiteSpace(x))),
            _ => ""
        };

    private static string FirstNotEmpty(params string[] values) =>
        values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "";

    private sealed record NetworkSignature(
        string GatewayMac, string DnsSuffix, string FirstNetwork, bool IsManaged);

    private sealed record NetworkAdapter(string Name, int? MediaSubType)
    {
        /// <summary>Тип носителя 2 — радиоинтерфейс Wi-Fi, 7 — Bluetooth.</summary>
        public bool IsWireless => MediaSubType == 2;
    }

    private sealed class NetworkInterfaceAddresses(
        string adapterGuid,
        string address,
        string gateway,
        string gatewayMac,
        string nameServer,
        string dhcpServer,
        string domain,
        string wifiName,
        DateTimeOffset? leaseObtainedUtc,
        DateTimeOffset? leaseEndsUtc)
    {
        public string AdapterGuid { get; } = adapterGuid;

        public string GatewayMac { get; } = gatewayMac;

        public string WifiName { get; } = wifiName;

        public DateTimeOffset? LeaseObtainedUtc { get; } = leaseObtainedUtc;

        /// <summary>К какой сети отнесли эти адреса; пусто — отнести не удалось.</summary>
        public string MatchedTo { get; set; } = "";

        /// <summary>
        /// Строки об адресах. Имя сетевого устройства нужно только там, где эти
        /// адреса идут сами по себе: у строки сети оно уже стоит отдельным
        /// полем, и в перечне адресов повторялось бы вторым разом.
        /// </summary>
        public List<string> Describe(string adapterName, bool withAdapter = true)
        {
            var lines = new List<string>();
            Add(lines, withAdapter && adapterName.Length > 0 ? $"подключение: {adapterName}" : "");
            Add(lines, address.Length > 0 ? $"адрес этой машины: {address}" : "");
            Add(lines, gateway.Length > 0 ? $"шлюз: {gateway}" : "");
            Add(lines, GatewayMac.Length > 0 ? $"MAC шлюза: {GatewayMac}" : "");
            Add(lines, nameServer.Length > 0 ? $"DNS: {nameServer}" : "");
            Add(lines, dhcpServer.Length > 0 ? $"сервер DHCP: {dhcpServer}" : "");
            Add(lines, domain.Length > 0 ? $"домен: {domain}" : "");
            Add(lines, LeaseObtainedUtc is not null
                ? $"адрес выдан: {DateDisplay.FormatMoscow(LeaseObtainedUtc)}"
                : "");
            Add(lines, leaseEndsUtc is not null
                ? $"аренда адреса до: {DateDisplay.FormatMoscow(leaseEndsUtc)}"
                : "");
            return lines;
        }

        private static void Add(List<string> lines, string line)
        {
            if (line.Length > 0)
            {
                lines.Add(line);
            }
        }
    }
}
