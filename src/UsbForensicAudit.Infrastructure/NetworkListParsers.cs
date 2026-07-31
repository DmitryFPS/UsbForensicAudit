using System.Globalization;
using System.Xml.Linq;

namespace UsbForensicAudit;

/// <summary>
/// Разбор значений, которыми Windows описывает сети. Вынесен отдельно от чтения
/// реестра: без этого проверить разбор дат и типов можно только на живой машине,
/// где значения меняются от запуска к запуску.
/// </summary>
internal static class NetworkListParsers
{
    /// <summary>
    /// Дата подключения к сети хранится структурой SYSTEMTIME в местном времени
    /// машины, а не в UTC. Разница видна сразу: запись «flash» о последнем
    /// подключении совпадает с событием журнала, только если считать её местной.
    /// </summary>
    internal static DateTimeOffset? TryReadSystemTime(byte[]? data)
    {
        if (data is null || data.Length < 16)
        {
            return null;
        }

        var year = BitConverter.ToUInt16(data, 0);
        var month = BitConverter.ToUInt16(data, 2);
        var day = BitConverter.ToUInt16(data, 6);
        var hour = BitConverter.ToUInt16(data, 8);
        var minute = BitConverter.ToUInt16(data, 10);
        var second = BitConverter.ToUInt16(data, 12);
        var millisecond = BitConverter.ToUInt16(data, 14);

        if (year is < 1980 or > 2200 || month is < 1 or > 12 || day is < 1 or > 31
            || hour > 23 || minute > 59 || second > 59 || millisecond > 999)
        {
            return null;
        }

        try
        {
            var local = new DateTime(year, month, day, hour, minute, second, millisecond,
                DateTimeKind.Unspecified);
            return new DateTimeOffset(DateTime.SpecifyKind(local, DateTimeKind.Local).ToUniversalTime());
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    /// <summary>
    /// NameType — это номер типа интерфейса по перечню IANA, тот же, что в
    /// сетевых счётчиках Windows. Раньше эти номера принимали за собственную
    /// нумерацию Windows, и профиль виртуального адаптера читался как «тип 53»
    /// без всякого смысла для читателя.
    /// </summary>
    internal static (string Kind, string Explanation) DescribeNameType(int nameType) => nameType switch
    {
        6 => (NetworkConnectionKind.Wired,
            "Тип интерфейса 6 — обычная сетевая карта: подключение по проводу."),
        71 => (NetworkConnectionKind.WiFi,
            "Тип интерфейса 71 — радиоинтерфейс 802.11: подключение по Wi-Fi."),
        23 => (NetworkConnectionKind.Vpn,
            "Тип интерфейса 23 — соединение PPP: так выглядят подключения по VPN и через модем."),
        53 => (NetworkConnectionKind.Vpn,
            "Тип интерфейса 53 — виртуальный сетевой адаптер: так выглядят клиенты VPN, "
            + "а также виртуальные коммутаторы систем виртуализации."),
        243 or 244 => (NetworkConnectionKind.MobileBroadband,
            "Тип интерфейса 243 — модем мобильной связи: подключение через сотовую сеть."),
        131 => (NetworkConnectionKind.Vpn,
            "Тип интерфейса 131 — туннель: так выглядят туннельные подключения, включая VPN."),
        24 => (NetworkConnectionKind.Unknown,
            "Тип интерфейса 24 — внутренняя петля самой машины, наружу такая связь не идёт."),
        _ => (NetworkConnectionKind.Unknown,
            $"Тип интерфейса {nameType} распознать не удалось: вид связи по нему определить нельзя.")
    };

    /// <summary>
    /// Категория сети из реестра. Влияет на брандмауэр и на видимость машины
    /// соседям по сети, поэтому в отчёте это не пустяк.
    /// </summary>
    internal static string DescribeCategory(int? category) => category switch
    {
        0 => "Общедоступная сеть",
        1 => "Частная сеть",
        2 => "Сеть домена",
        _ => ""
    };

    internal static string FormatMac(byte[]? data) =>
        data is null || data.Length < 6
            ? ""
            : string.Join(":", data.Take(6).Select(x => x.ToString("x2", CultureInfo.InvariantCulture)));

    /// <summary>
    /// Адрес шлюза и его MAC лежат в одном значении: четыре байта адреса, длина
    /// аппаратного адреса и сам адрес. По MAC шлюза различаются две сети с
    /// одинаковым именем — например, домашняя и рабочая «flash».
    /// </summary>
    internal static (string Gateway, string GatewayMac) ReadGatewayHardware(byte[]? data)
    {
        if (data is null || data.Length < 14)
        {
            return ("", "");
        }

        var gateway = string.Join(".", data.Take(4).Select(x => x.ToString(CultureInfo.InvariantCulture)));
        return (gateway, FormatMac(data.Skip(8).Take(6).ToArray()));
    }

    /// <summary>
    /// DhcpNetworkHint — имя сети Wi-Fi, записанное шестнадцатеричными знаками, у
    /// которых внутри каждого байта половинки переставлены местами: «flash» это
    /// «666C617368», а в реестре лежит «66C6163786». Это единственная надёжная
    /// связь между выданным машине адресом и именем сети.
    /// </summary>
    internal static string DecodeNetworkHint(string? hint)
    {
        var text = (hint ?? "").Trim();
        if (text.Length == 0 || text.Length % 2 != 0 || !text.All(Uri.IsHexDigit))
        {
            return "";
        }

        var bytes = new byte[text.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            var stored = Convert.ToByte(text.Substring(i * 2, 2), 16);
            bytes[i] = (byte)(((stored & 0x0F) << 4) | (stored >> 4));
        }

        var name = System.Text.Encoding.UTF8.GetString(bytes).TrimEnd('\0');
        return name.Length > 0 && name.All(x => !char.IsControl(x)) ? name : "";
    }

    /// <summary>
    /// Сохранённый профиль Wi-Fi. Пароль в нём лежит зашифрованным на ключе
    /// машины, и расшифровывать его аудит не должен: для отчёта важно, каким
    /// способом сеть защищена, а не чем именно она открывается.
    /// </summary>
    internal static WlanProfileInfo? ParseWlanProfile(string? xml)
    {
        if (string.IsNullOrWhiteSpace(xml))
        {
            return null;
        }

        try
        {
            var document = XDocument.Parse(xml);
            var root = document.Root;
            if (root is null)
            {
                return null;
            }

            var ns = root.Name.Namespace;
            var ssid = root.Element(ns + "SSIDConfig")?.Element(ns + "SSID");
            var security = root.Element(ns + "MSM")?.Element(ns + "security");
            var authEncryption = security?.Element(ns + "authEncryption");

            return new WlanProfileInfo(
                Name: root.Element(ns + "name")?.Value ?? "",
                Ssid: ssid?.Element(ns + "name")?.Value ?? "",
                Authentication: DescribeAuthentication(authEncryption?.Element(ns + "authentication")?.Value),
                Encryption: DescribeEncryption(authEncryption?.Element(ns + "encryption")?.Value),
                ConnectionMode: DescribeConnectionMode(root.Element(ns + "connectionMode")?.Value),
                HasStoredKey: security?.Element(ns + "sharedKey")?.Element(ns + "keyMaterial") is not null);
        }
        catch (System.Xml.XmlException)
        {
            return null;
        }
    }

    private static string DescribeAuthentication(string? value) => value switch
    {
        null or "" => "",
        "open" => "открытая сеть без пароля",
        "shared" => "общий ключ WEP",
        "WPA" => "WPA-Enterprise",
        "WPAPSK" => "WPA-Personal",
        "WPA2" => "WPA2-Enterprise",
        "WPA2PSK" => "WPA2-Personal",
        "WPA3" or "WPA3ENT" or "WPA3ENT192" => "WPA3-Enterprise",
        "WPA3SAE" => "WPA3-Personal",
        _ => value
    };

    private static string DescribeEncryption(string? value) => value switch
    {
        null or "" => "",
        "none" => "без шифрования",
        "WEP" => "WEP",
        "TKIP" => "TKIP",
        "AES" => "AES",
        "GCMP256" => "GCMP-256",
        _ => value
    };

    private static string DescribeConnectionMode(string? value) => value switch
    {
        "auto" => "подключается автоматически",
        "manual" => "подключается вручную",
        _ => ""
    };
}

/// <summary>Сохранённый профиль сети Wi-Fi в том виде, в каком он нужен отчёту.</summary>
internal sealed record WlanProfileInfo(
    string Name,
    string Ssid,
    string Authentication,
    string Encryption,
    string ConnectionMode,
    bool HasStoredKey)
{
    /// <summary>Чем защищена сеть, одной строкой для столбца отчёта.</summary>
    public string SecurityText
    {
        get
        {
            var parts = new[] { Authentication, Encryption }.Where(x => x.Length > 0).ToArray();
            return parts.Length == 0 ? "" : string.Join(", ", parts);
        }
    }
}
