using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Фильтрация служебного шума из таблицы соседей и добыча имён устройств
/// по NetBIOS, mDNS и результатам полного аудита машины.
/// </summary>
public class NetworkNameDiscoveryTests
{
    [Theory]
    [InlineData("224.0.0.22")] // групповая рассылка IGMP
    [InlineData("239.255.255.250")] // групповая рассылка SSDP
    [InlineData("255.255.255.255")] // широковещание
    [InlineData("169.254.10.20")] // link-local без DHCP
    [InlineData("127.0.0.1")] // петля
    [InlineData("0.0.0.0")]
    [InlineData("ff02::fb")] // mDNS IPv6
    [InlineData("fe80::1")] // link-local IPv6
    [InlineData("не адрес")]
    [InlineData("")]
    public void Service_noise_is_not_a_device(string address)
    {
        Assert.True(NetworkAddressFilter.IsNoise(address));
    }

    [Theory]
    [InlineData("192.168.1.10")]
    [InlineData("10.0.0.5")]
    [InlineData("172.16.4.1")]
    public void Real_lan_addresses_pass_the_filter(string address)
    {
        Assert.False(NetworkAddressFilter.IsNoise(address));
    }

    [Theory]
    [InlineData("TAP-Windows Adapter V9", true)]
    [InlineData("WireGuard Tunnel", true)]
    [InlineData("Hyper-V Virtual Ethernet Adapter", true)]
    [InlineData("Intel(R) Ethernet Connection I219-V", false)]
    [InlineData("Realtek 8822CE Wireless LAN 802.11ac", false)]
    [InlineData("", false)]
    public void Virtual_adapters_are_recognized_by_description(string description, bool expected)
    {
        Assert.Equal(expected, NetworkAddressFilter.IsVirtualAdapterDescription(description));
    }

    [Fact]
    public void Netbios_request_is_well_formed()
    {
        var packet = NetbiosNameProtocol.BuildNodeStatusRequest(0xBEEF);

        Assert.Equal(50, packet.Length);
        Assert.Equal(0xBE, packet[0]);
        Assert.Equal(0xEF, packet[1]);
        Assert.Equal(1, packet[5]); // один вопрос
        Assert.Equal(0x21, packet[47]); // QTYPE = NBSTAT
    }

    [Fact]
    public void Netbios_response_yields_workstation_name()
    {
        const ushort tid = 0x1234;
        var response = BuildNetbiosResponse(tid, "PC-01", suffix: 0x00, groupFlag: false);

        Assert.Equal("PC-01", NetbiosNameProtocol.ParseNodeStatusResponse(response, tid));
    }

    [Fact]
    public void Netbios_group_names_are_ignored()
    {
        const ushort tid = 0x1234;
        var response = BuildNetbiosResponse(tid, "WORKGROUP", suffix: 0x00, groupFlag: true);

        Assert.Equal("", NetbiosNameProtocol.ParseNodeStatusResponse(response, tid));
    }

    [Fact]
    public void Netbios_response_with_wrong_transaction_is_rejected()
    {
        var response = BuildNetbiosResponse(0x1111, "PC-01", suffix: 0x00, groupFlag: false);

        Assert.Equal("", NetbiosNameProtocol.ParseNodeStatusResponse(response, 0x2222));
    }

    [Fact]
    public void Mdns_query_encodes_reverse_address()
    {
        var packet = MulticastDnsProtocol.BuildReversePtrQuery("192.168.1.15", 0x0001);

        Assert.NotEmpty(packet);
        var text = Encoding.ASCII.GetString(packet);
        Assert.Contains("in-addr", text);
        Assert.Contains("15", text);
    }

    [Fact]
    public void Mdns_query_for_bad_address_is_empty()
    {
        Assert.Empty(MulticastDnsProtocol.BuildReversePtrQuery("не адрес", 1));
    }

    [Fact]
    public void Mdns_response_yields_name_without_local_suffix()
    {
        var response = BuildMdnsPtrResponse("my-phone.local");

        Assert.Equal("my-phone", MulticastDnsProtocol.ParsePtrResponse(response, 0x0001));
    }

    [Fact]
    public void Audit_enrichment_names_bluetooth_phone_by_mac()
    {
        var neighbor = new NetworkNeighborRecord
        {
            IpAddress = "192.168.1.20",
            MacAddress = "AA:BB:CC:DD:EE:FF"
        };
        var device = new UsbDeviceRecord
        {
            FriendlyName = "Pixel 8 Pro",
            Serial = "aabbccddeeff"
        };

        NeighborAuditEnrichment.Enrich([neighbor], [device]);

        Assert.Equal("Pixel 8 Pro", neighbor.EnrichedName);
        Assert.Equal(NeighborAuditEnrichment.SourceName, neighbor.NameSource);
        Assert.Equal("Pixel 8 Pro", neighbor.NameText);
    }

    [Fact]
    public void Audit_enrichment_does_not_override_network_names()
    {
        var neighbor = new NetworkNeighborRecord
        {
            IpAddress = "192.168.1.20",
            MacAddress = "AA:BB:CC:DD:EE:FF",
            HostName = "printer.lan"
        };

        NeighborAuditEnrichment.Enrich(
            [neighbor],
            [new UsbDeviceRecord { FriendlyName = "Pixel", Serial = "AABBCCDDEEFF" }]);

        Assert.Equal("", neighbor.EnrichedName);
        Assert.Equal("printer.lan", neighbor.NameText);
    }

    [Fact]
    public void Name_source_text_explains_missing_names()
    {
        var silent = new NetworkNeighborRecord { IpAddress = "192.168.1.30" };
        var named = new NetworkNeighborRecord
        {
            IpAddress = "192.168.1.31",
            HostName = "nas.lan",
            NameSource = "обратный DNS"
        };

        Assert.Equal("имя не получено", silent.NameSourceText);
        Assert.Equal("обратный DNS", named.NameSourceText);
    }

    private static byte[] BuildNetbiosResponse(ushort tid, string name, byte suffix, bool groupFlag)
    {
        // Заголовок + имя вопроса (34) + тип/класс (4) + TTL (4) + RDLENGTH (2).
        const int nameCountOffset = 12 + 34 + 4 + 4 + 2;
        var packet = new byte[nameCountOffset + 1 + 18];
        packet[0] = (byte)(tid >> 8);
        packet[1] = (byte)tid;
        packet[2] = 0x84; // это ответ
        packet[nameCountOffset] = 1;

        var entry = nameCountOffset + 1;
        var padded = name.PadRight(15);
        Encoding.ASCII.GetBytes(padded, packet.AsSpan(entry, 15));
        packet[entry + 15] = suffix;
        packet[entry + 16] = groupFlag ? (byte)0x80 : (byte)0x04;
        packet[entry + 17] = 0x00;
        return packet;
    }

    private static byte[] BuildMdnsPtrResponse(string targetName)
    {
        var packet = new List<byte>
        {
            0x00, 0x01, // transaction id
            0x84, 0x00, // ответ, авторитетный
            0x00, 0x00, // вопросов нет
            0x00, 0x01, // один ответ
            0x00, 0x00, 0x00, 0x00
        };

        // Имя владельца записи: 20.1.168.192.in-addr.arpa.
        AppendName(packet, "20.1.168.192.in-addr.arpa");
        packet.AddRange([0x00, 0x0C]); // PTR
        packet.AddRange([0x00, 0x01]); // IN
        packet.AddRange([0x00, 0x00, 0x00, 0x78]); // TTL

        var data = new List<byte>();
        AppendName(data, targetName);
        packet.Add((byte)(data.Count >> 8));
        packet.Add((byte)data.Count);
        packet.AddRange(data);
        return [.. packet];
    }

    private static void AppendName(List<byte> packet, string name)
    {
        foreach (var label in name.Split('.'))
        {
            var encoded = Encoding.ASCII.GetBytes(label);
            packet.Add((byte)encoded.Length);
            packet.AddRange(encoded);
        }

        packet.Add(0x00);
    }
}
