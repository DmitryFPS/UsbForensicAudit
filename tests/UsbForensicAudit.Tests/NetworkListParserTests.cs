using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Значения взяты с живой машины: список сетей, подписи сетей и параметры
/// интерфейсов. Разбор проверяется на них, а не на выдуманных байтах, иначе
/// ошибка в порядке полей или в часовом поясе остаётся незамеченной.
/// </summary>
public class NetworkListParserTests
{
    /// <summary>
    /// «flash», последнее подключение: ea 07 07 00 05 00 1f 00 12 00 18 00 25 00 91 00.
    /// Год 2026, месяц 7, день недели 5 (пятница), день 31, 18:24:37.145.
    /// </summary>
    [Fact]
    public void Last_connection_date_is_read_as_local_time_of_the_machine()
    {
        byte[] raw =
        [
            0xea, 0x07, 0x07, 0x00, 0x05, 0x00, 0x1f, 0x00,
            0x12, 0x00, 0x18, 0x00, 0x25, 0x00, 0x91, 0x00
        ];

        var moment = NetworkListParsers.TryReadSystemTime(raw);

        Assert.NotNull(moment);
        var local = moment.Value.ToOffset(TimeZoneInfo.Local.GetUtcOffset(moment.Value));
        Assert.Equal(new DateTime(2026, 7, 31, 18, 24, 37, 145), local.DateTime);
    }

    /// <summary>
    /// Значение в местном времени, а не в UTC: иначе дата последнего подключения
    /// расходится с событием журнала на величину часового пояса, и отчёт
    /// показывает подключение, которого в это время не было.
    /// </summary>
    [Fact]
    public void Date_is_not_treated_as_utc()
    {
        byte[] raw =
        [
            0xea, 0x07, 0x07, 0x00, 0x05, 0x00, 0x1f, 0x00,
            0x12, 0x00, 0x18, 0x00, 0x25, 0x00, 0x91, 0x00
        ];

        var moment = NetworkListParsers.TryReadSystemTime(raw);

        Assert.NotNull(moment);
        var offset = TimeZoneInfo.Local.GetUtcOffset(moment.Value);
        Assert.Equal(new DateTime(2026, 7, 31, 18, 24, 37, 145) - offset, moment.Value.UtcDateTime);
    }

    [Fact]
    public void Nonsense_bytes_do_not_become_a_date()
    {
        Assert.Null(NetworkListParsers.TryReadSystemTime(null));
        Assert.Null(NetworkListParsers.TryReadSystemTime([0x01, 0x02]));
        Assert.Null(NetworkListParsers.TryReadSystemTime(new byte[16]));
    }

    /// <summary>
    /// NameType — номер типа интерфейса по перечню IANA. Значения взяты с живой
    /// машины: 71 у сети Wi-Fi «flash», 6 у проводной «Сеть», 53 у «SigmaVPN».
    /// </summary>
    [Theory]
    [InlineData(71, NetworkConnectionKind.WiFi)]
    [InlineData(6, NetworkConnectionKind.Wired)]
    [InlineData(53, NetworkConnectionKind.Vpn)]
    [InlineData(23, NetworkConnectionKind.Vpn)]
    [InlineData(243, NetworkConnectionKind.MobileBroadband)]
    public void Interface_type_number_becomes_a_kind_of_link(int nameType, string expected)
    {
        var (kind, explanation) = NetworkListParsers.DescribeNameType(nameType);

        Assert.Equal(expected, kind);
        Assert.Contains(nameType.ToString(), explanation);
    }

    [Fact]
    public void Unknown_interface_type_says_so_instead_of_guessing()
    {
        var (kind, explanation) = NetworkListParsers.DescribeNameType(199);

        Assert.Equal(NetworkConnectionKind.Unknown, kind);
        Assert.Contains("199", explanation);
        Assert.Contains("нельзя", explanation);
    }

    [Fact]
    public void Gateway_mac_is_read_from_the_signature()
    {
        byte[] raw = [0xd4, 0x01, 0xc3, 0x31, 0xd0, 0x48];

        Assert.Equal("d4:01:c3:31:d0:48", NetworkListParsers.FormatMac(raw));
        Assert.Equal("", NetworkListParsers.FormatMac(null));
        Assert.Equal("", NetworkListParsers.FormatMac([0x01]));
    }

    /// <summary>
    /// DhcpGatewayHardware с живой машины: адрес шлюза, длина аппаратного адреса
    /// и сам MAC в одном значении.
    /// </summary>
    [Fact]
    public void Gateway_address_and_its_mac_come_from_one_value()
    {
        byte[] raw =
        [
            0xc0, 0xa8, 0x01, 0x01, 0x06, 0x00, 0x00, 0x00,
            0xd4, 0x01, 0xc3, 0x31, 0xd0, 0x48
        ];

        var (gateway, mac) = NetworkListParsers.ReadGatewayHardware(raw);

        Assert.Equal("192.168.1.1", gateway);
        Assert.Equal("d4:01:c3:31:d0:48", mac);
    }

    /// <summary>
    /// «flash» в подсказке лежит как «66C6163786»: это шестнадцатеричная запись
    /// имени, у которой внутри каждого байта половинки переставлены.
    /// </summary>
    [Theory]
    [InlineData("66C6163786", "flash")]
    [InlineData("66C61637860223", "flash 2")]
    public void Network_hint_gives_back_the_name_of_the_wifi_network(string hint, string expected) =>
        Assert.Equal(expected, NetworkListParsers.DecodeNetworkHint(hint));

    [Fact]
    public void Broken_hint_does_not_produce_a_name()
    {
        Assert.Equal("", NetworkListParsers.DecodeNetworkHint(""));
        Assert.Equal("", NetworkListParsers.DecodeNetworkHint(null));
        Assert.Equal("", NetworkListParsers.DecodeNetworkHint("ZZZZ"));
        Assert.Equal("", NetworkListParsers.DecodeNetworkHint("66C61637"[..3]));
    }

    /// <summary>Профиль Wi-Fi с живой машины, ключ вырезан.</summary>
    private const string WlanProfileXml = """
        <?xml version="1.0"?>
        <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
        	<name>flash</name>
        	<SSIDConfig>
        		<SSID>
        			<hex>666C617368</hex>
        			<name>flash</name>
        		</SSID>
        	</SSIDConfig>
        	<connectionType>ESS</connectionType>
        	<connectionMode>manual</connectionMode>
        	<MSM>
        		<security>
        			<authEncryption>
        				<authentication>WPA2PSK</authentication>
        				<encryption>AES</encryption>
        				<useOneX>false</useOneX>
        			</authEncryption>
        			<sharedKey>
        				<keyType>passPhrase</keyType>
        				<protected>true</protected>
        				<keyMaterial>01000000D08C9DDF</keyMaterial>
        			</sharedKey>
        		</security>
        	</MSM>
        </WLANProfile>
        """;

    [Fact]
    public void Saved_wifi_profile_tells_how_the_network_is_protected()
    {
        var profile = NetworkListParsers.ParseWlanProfile(WlanProfileXml);

        Assert.NotNull(profile);
        Assert.Equal("flash", profile.Name);
        Assert.Equal("flash", profile.Ssid);
        Assert.Equal("WPA2-Personal, AES", profile.SecurityText);
        Assert.Equal("подключается вручную", profile.ConnectionMode);
        Assert.True(profile.HasStoredKey);
    }

    [Fact]
    public void Open_network_is_named_as_open_not_left_blank()
    {
        var profile = NetworkListParsers.ParseWlanProfile("""
            <?xml version="1.0"?>
            <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
            	<name>Гостевая</name>
            	<MSM><security><authEncryption>
            		<authentication>open</authentication><encryption>none</encryption>
            	</authEncryption></security></MSM>
            </WLANProfile>
            """);

        Assert.NotNull(profile);
        Assert.Equal("открытая сеть без пароля, без шифрования", profile.SecurityText);
        Assert.False(profile.HasStoredKey);
    }

    [Fact]
    public void Broken_profile_xml_does_not_break_the_scan()
    {
        Assert.Null(NetworkListParsers.ParseWlanProfile("не разметка вовсе"));
        Assert.Null(NetworkListParsers.ParseWlanProfile(""));
        Assert.Null(NetworkListParsers.ParseWlanProfile(null));
    }

    [Theory]
    [InlineData(0, "Общедоступная сеть")]
    [InlineData(1, "Частная сеть")]
    [InlineData(2, "Сеть домена")]
    [InlineData(null, "")]
    public void Category_is_named_in_plain_words(int? category, string expected) =>
        Assert.Equal(expected, NetworkListParsers.DescribeCategory(category));
}
