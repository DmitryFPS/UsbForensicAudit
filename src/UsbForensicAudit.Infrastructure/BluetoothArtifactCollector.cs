using System.Text;
using Microsoft.Win32;

namespace UsbForensicAudit;

/// <summary>
/// Сопряжения по Bluetooth и наличие NFC.
///
/// Сопряжённое устройство Windows запоминает надолго: имя, адрес, класс,
/// последнее соединение и перечень услуг остаются в реестре и после того, как
/// устройство унесли. Для проверки это ценно: телефон, сопряжённый с рабочей
/// машиной, — канал, по которому файлы уходят без всякой флешки.
///
/// NFC проверяется отдельно и всегда: молчание о нём читается как «не
/// подключали», хотя означать может «оборудования нет вовсе».
/// </summary>
internal sealed class BluetoothArtifactCollector : INetworkArtifactCollector
{
    private const string DevicesPath = @"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices";
    private const string ClassicEnumPath = @"SYSTEM\CurrentControlSet\Enum\BTHENUM";
    private const string LowEnergyEnumPath = @"SYSTEM\CurrentControlSet\Enum\BTHLE";
    private const string SourceName = "Реестр Windows — сопряжения Bluetooth";

    /// <summary>Пометка услуги, через которую данные могут уйти с машины или прийти на неё.</summary>
    private const string NotableMark = "!";

    public string ProgressMessage => "Чтение сопряжений Bluetooth и проверка NFC...";

    public bool ShouldRun => true;

    public NetworkArtifactSet Collect(List<string> warnings)
    {
        var evidence = new List<EvidenceRecord> { NearFieldPresence.Describe() };
        var connections = new List<NetworkConnectionRecord>();

        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(DevicesPath);
            if (root is null)
            {
                evidence.Add(NoRadio());
                return new NetworkArtifactSet(connections, evidence);
            }

            var names = ReadEnumeratedNames(ClassicEnumPath, warnings);
            var services = ReadEnumeratedServices(warnings);
            var lowEnergy = ReadLowEnergyAddresses(warnings);

            foreach (var address in root.GetSubKeyNames())
            {
                using var key = root.OpenSubKey(address);
                if (key is null)
                {
                    continue;
                }

                connections.Add(BuildDevice(address, key, names, services, lowEnergy));
            }

            if (connections.Count == 0)
            {
                evidence.Add(NoPairings());
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Сопряжения Bluetooth прочитаны не полностью: {exception.Message}. "
                         + "Ветка сопряжений закрыта от чтения всем, кроме системы: без прав системы "
                         + "перечень сопряжённых устройств остаётся неизвестным.");
        }

        return new NetworkArtifactSet(connections, evidence);
    }

    private static NetworkConnectionRecord BuildDevice(
        string address,
        RegistryKey key,
        Dictionary<string, string> names,
        Dictionary<string, List<string>> services,
        HashSet<string> lowEnergy)
    {
        var mac = FormatMac(address);
        var name = FirstNotEmpty(
            names.TryGetValue(address, out var friendly) ? friendly : "",
            ReadBinaryName(key),
            mac);

        var classOfDevice = key.GetValue("COD") as int?;
        var deviceClass = BluetoothServiceCatalog.DescribeDeviceClass(classOfDevice);
        var abilities = BluetoothServiceCatalog.DescribeServiceClasses(classOfDevice);
        var deviceServices = services.TryGetValue(address, out var list) ? list : [];

        var lastConnected = ReadFileTime(key, "LastConnected");
        var lastSeen = ReadFileTime(key, "LastSeen");

        var record = new NetworkConnectionRecord
        {
            Kind = NetworkConnectionKind.Bluetooth,
            Name = name,
            Address = mac,
            Adapter = "Радиомодуль Bluetooth этой машины",
            Security = DescribePairing(key),
            // Даты сопряжения Windows не хранит вовсе: в записи есть только последнее
            // соединение и последнее обнаружение. Оставить клетку пустой значит
            // потерять единственные известные даты, поэтому в первую ставится ранняя
            // из двух, а рядом сказано, что первым подключением она не является.
            FirstSeenUtc = Earlier(lastConnected, lastSeen),
            FirstSeenProvenance = "Даты сопряжения Windows не хранит: в записи устройства есть только "
                                  + "последнее соединение и последнее обнаружение. Здесь стоит ранняя из "
                                  + "этих двух дат, и первым подключением она не является",
            LastSeenUtc = Later(lastConnected, lastSeen),
            LastSeenProvenance = (lastConnected is not null
                                     ? $@"LastConnected в HKLM\{DevicesPath}\{address}"
                                     : $@"LastSeen в HKLM\{DevicesPath}\{address}")
                                 + "; значение записано в местном времени машины и приведено к UTC",
            Source = SourceName,
            Provenance = $@"HKLM\{DevicesPath}\{address}",
            Details = BuildDetails(deviceClass, abilities, deviceServices, lowEnergy.Contains(address))
        };

        if (lastConnected is not null)
        {
            record.Sessions.Add(new NetworkSession
            {
                StartedUtc = lastConnected,
                IsMoment = true,
                Outcome = "Последнее соединение этой машины с устройством",
                Reason = "Дата взята из записи сопряжения: она хранит только последнее соединение, "
                         + "поэтому сколько их было всего, по ней сказать нельзя",
                Source = SourceName,
                Provenance = $@"LastConnected в HKLM\{DevicesPath}\{address}"
            });
        }

        if (lastSeen is not null && lastSeen != lastConnected)
        {
            record.Sessions.Add(new NetworkSession
            {
                StartedUtc = lastSeen,
                IsMoment = true,
                Outcome = "Устройство последний раз было в радиусе связи",
                Reason = "Устройство отозвалось на запрос радиомодуля. Соединения это не означает: "
                         + "включённый телефон рядом с машиной отзывается и без него",
                Source = SourceName,
                Provenance = $@"LastSeen в HKLM\{DevicesPath}\{address}"
            });
        }

        return record;
    }

    private static string BuildDetails(
        string deviceClass,
        List<string> abilities,
        List<string> services,
        bool hasLowEnergy)
    {
        var parts = new List<string>
        {
            "Устройство записано в списке сопряжённых устройств Bluetooth этой машины"
        };

        if (deviceClass.Length > 0)
        {
            parts.Add($"класс устройства по его собственным словам: {deviceClass}");
        }

        if (services.Count > 0)
        {
            var transfer = services.Where(x => x.StartsWith(NotableMark, StringComparison.Ordinal))
                .Select(x => x[NotableMark.Length..]).ToList();
            var other = services.Where(x => !x.StartsWith(NotableMark, StringComparison.Ordinal)).ToList();

            if (transfer.Count > 0)
            {
                parts.Add($"через это соединение были доступны перенос данных и связь: "
                          + string.Join("; ", transfer));
            }

            if (other.Count > 0)
            {
                parts.Add($"прочие услуги: {string.Join("; ", other)}");
            }
        }
        else
        {
            // Возможности из класса устройства грубее перечня услуг и рядом с ним
            // только повторяли бы его другими словами. Без перечня они — всё, что
            // о назначении соединения известно.
            if (abilities.Count > 0)
            {
                parts.Add($"устройство объявило о себе: {string.Join(", ", abilities)}");
            }

            parts.Add("перечня услуг в реестре не сохранилось, поэтому что именно было доступно через "
                      + "это соединение, по нему не сказать");
        }

        if (hasLowEnergy)
        {
            parts.Add("устройство работало и по Bluetooth малой мощности");
        }

        return string.Join(". ", parts);
    }

    /// <summary>
    /// Чем защищено сопряжение. Слово «сопряжено» здесь не украшение: без него
    /// в клетке защиты стояла бы пустота, которая читается как «защиты нет».
    /// </summary>
    private static string DescribePairing(RegistryKey key)
    {
        foreach (var name in key.GetSubKeyNames()
                     .Where(x => x.StartsWith("ServicesFor", StringComparison.OrdinalIgnoreCase)))
        {
            using var child = key.OpenSubKey(name);
            if (child is null)
            {
                continue;
            }

            var secure = child.GetValue("SSP Paired") as int? ?? 0;
            var protectedFromInterception = child.GetValue("SSP MITM Protected") as int? ?? 0;
            return secure != 0
                ? protectedFromInterception != 0
                    ? "Сопряжение с защитой от перехвата (Secure Simple Pairing с подтверждением)"
                    : "Сопряжение по Secure Simple Pairing без подтверждения на устройстве"
                : "Сопряжение состоялось; способ подтверждения Windows не записала";
        }

        return "Сопряжение состоялось; способ подтверждения Windows не записала";
    }

    /// <summary>
    /// Имена сопряжённых устройств из перечисления устройств. Там имя лежит
    /// обычной строкой, тогда как в записи сопряжения — двоичным значением.
    /// </summary>
    private static Dictionary<string, string> ReadEnumeratedNames(string path, List<string> warnings)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(path);
            if (root is null)
            {
                return result;
            }

            foreach (var device in root.GetSubKeyNames()
                         .Where(x => x.StartsWith("Dev_", StringComparison.OrdinalIgnoreCase)))
            {
                var address = device[4..];
                using var deviceKey = root.OpenSubKey(device);
                foreach (var instance in deviceKey?.GetSubKeyNames() ?? [])
                {
                    using var instanceKey = deviceKey!.OpenSubKey(instance);
                    var name = FirstNotEmpty(
                        instanceKey?.GetValue("FriendlyName") as string ?? "",
                        CleanDeviceDescription(instanceKey?.GetValue("DeviceDesc") as string ?? ""));

                    if (name.Length > 0 && !result.ContainsKey(address))
                    {
                        result[address] = name;
                    }
                }
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Имена устройств Bluetooth прочитаны не полностью: {exception.Message}");
        }

        return result;
    }

    /// <summary>
    /// Услуги, которыми пользовалось каждое устройство. Windows создаёт для
    /// каждой услуги отдельную запись перечисления с её опознавателем и с
    /// изготовителем устройства в имени.
    /// </summary>
    private static Dictionary<string, List<string>> ReadEnumeratedServices(List<string> warnings)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(ClassicEnumPath);
            if (root is null)
            {
                return result;
            }

            foreach (var name in root.GetSubKeyNames().Where(x => x.StartsWith("{", StringComparison.Ordinal)))
            {
                if (!BluetoothServiceCatalog.TryDescribe(name, out var description, out var notable))
                {
                    continue;
                }

                using var serviceKey = root.OpenSubKey(name);
                foreach (var instance in serviceKey?.GetSubKeyNames() ?? [])
                {
                    using var instanceKey = serviceKey!.OpenSubKey(instance);
                    var address = ReadAddressOfService(instanceKey);
                    if (address.Length == 0)
                    {
                        continue;
                    }

                    if (!result.TryGetValue(address, out var list))
                    {
                        list = [];
                        result[address] = list;
                    }

                    // Услуги переноса данных идут первыми: в длинном перечне звуковых
                    // услуг телефона именно они отвечают на вопрос проверки.
                    var text = notable ? NotableMark + description : description;
                    if (!list.Contains(text, StringComparer.OrdinalIgnoreCase))
                    {
                        list.Add(text);
                    }
                }
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Услуги устройств Bluetooth прочитаны не полностью: {exception.Message}");
        }

        return result;
    }

    /// <summary>
    /// Адрес устройства, к которому относится запись услуги. Он записан в
    /// опознавателе устройства вида «{…}#887598C2F5F2_00000000» или в самом
    /// имени записи перечисления.
    /// </summary>
    private static string ReadAddressOfService(RegistryKey? instanceKey)
    {
        if (instanceKey is null)
        {
            return "";
        }

        using var parameters = instanceKey.OpenSubKey("Device Parameters");
        var unique = parameters?.GetValue("Bluetooth_UniqueID") as string ?? "";
        var separator = unique.IndexOf('#');
        if (separator >= 0)
        {
            var tail = unique[(separator + 1)..].Split('_')[0];
            if (IsAddress(tail))
            {
                return tail;
            }
        }

        foreach (var part in (instanceKey.Name ?? "").Split('&', '\\', '_'))
        {
            if (IsAddress(part))
            {
                return part;
            }
        }

        return "";
    }

    private static HashSet<string> ReadLowEnergyAddresses(List<string> warnings)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(LowEnergyEnumPath);
            foreach (var name in root?.GetSubKeyNames() ?? [])
            {
                if (name.StartsWith("Dev_", StringComparison.OrdinalIgnoreCase) && IsAddress(name[4..]))
                {
                    result.Add(name[4..]);
                }
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Устройства Bluetooth малой мощности прочитаны не полностью: {exception.Message}");
        }

        return result;
    }

    /// <summary>
    /// Имя устройства из записи сопряжения. Оно записано не строкой, а набором
    /// байтов в кодировке UTF-8: имя «Galaxy S9+ пользователя Дмитрий» при
    /// чтении как строки превращалось в набор иероглифов.
    /// </summary>
    private static string ReadBinaryName(RegistryKey key)
    {
        if (key.GetValue("Name") is not byte[] bytes || bytes.Length == 0)
        {
            return "";
        }

        var text = Encoding.UTF8.GetString(bytes).TrimEnd('\0').Trim();
        return TextSanitizer.IsReadableForDisplay(text) ? text : "";
    }

    /// <summary>
    /// Время из записи сопряжения. Хранится оно счётчиком, каким Windows обычно
    /// хранит время по Гринвичу, но записано в местном времени машины: значение
    /// LastSeen на проверяемой машине оказалось ровно на часовой поясной сдвиг
    /// больше времени последней правки самого ключа. Прочитанное как время по
    /// Гринвичу, оно давало дату в будущем — «телефон был рядом» на три часа
    /// позже, чем шла проверка.
    /// </summary>
    private static DateTimeOffset? ReadFileTime(RegistryKey key, string name)
    {
        if (key.GetValue(name) is not long value || value <= 0)
        {
            return null;
        }

        try
        {
            var written = DateTime.SpecifyKind(DateTime.FromFileTimeUtc(value), DateTimeKind.Unspecified);
            return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(written, TimeZoneInfo.Local));
        }
        catch (Exception exception)
            when (exception is ArgumentOutOfRangeException or ArgumentException)
        {
            return null;
        }
    }

    private static string FirstNotEmpty(params string[] values) =>
        values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim() ?? "";

    private static DateTimeOffset? Later(DateTimeOffset? first, DateTimeOffset? second) =>
        first is null ? second : second is null ? first : first > second ? first : second;

    private static DateTimeOffset? Earlier(DateTimeOffset? first, DateTimeOffset? second) =>
        first is null ? second : second is null ? first : first < second ? first : second;

    private static bool IsAddress(string value) =>
        value.Length == 12 && value.All(Uri.IsHexDigit);

    private static string FormatMac(string address)
    {
        if (!IsAddress(address))
        {
            return address;
        }

        return string.Join(':', Enumerable.Range(0, 6)
            .Select(i => address.Substring(i * 2, 2).ToUpperInvariant()));
    }

    /// <summary>
    /// Описание устройства Windows хранит ссылкой на файл описания драйвера:
    /// «@bth.inf,%bthenum\generic_device%;Bluetooth Device». Человеку нужна
    /// только часть после точки с запятой.
    /// </summary>
    private static string CleanDeviceDescription(string value)
    {
        var separator = value.LastIndexOf(';');
        return separator >= 0 ? value[(separator + 1)..].Trim() : value.Trim();
    }

    private static EvidenceRecord NoRadio() => new()
    {
        TimestampUtc = DateTimeOffset.UtcNow,
        Source = SourceName,
        EvidenceCategory = "Bluetooth на этой машине",
        EvidenceStrength = "Context",
        Confidence = "High",
        CanEstablishConnectionDate = false,
        Summary = "Ветки сопряжений Bluetooth в реестре нет.",
        UserExplanation = "Ветка появляется вместе с радиомодулем Bluetooth. Её отсутствие означает, "
                          + "что радиомодуля на машине нет или его драйвер никогда не устанавливался, "
                          + "а значит, сопряжений быть не могло.",
        Provenance = $@"HKLM\{DevicesPath}"
    };

    private static EvidenceRecord NoPairings() => new()
    {
        TimestampUtc = DateTimeOffset.UtcNow,
        Source = SourceName,
        EvidenceCategory = "Bluetooth на этой машине",
        EvidenceStrength = "Context",
        Confidence = "High",
        CanEstablishConnectionDate = false,
        Summary = "Радиомодуль Bluetooth есть, сопряжённых устройств не записано.",
        UserExplanation = "Записи о сопряжениях хранятся до их удаления вручную или сброса Bluetooth. "
                          + "Пустой список означает, что сопряжений не было либо их удалили; сама "
                          + "ветка при удалении сопряжения остаётся.",
        Provenance = $@"HKLM\{DevicesPath}"
    };
}
