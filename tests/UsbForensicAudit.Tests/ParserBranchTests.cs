using System.IO;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Ветви разбора внешних форматов: экспорт реестра, профили WLAN, пакеты mDNS,
/// классы Bluetooth-устройств, коды завершения SMB и справочники устройств.
/// </summary>
public sealed class ParserBranchTests
{
    // ---------- RegExportParser ----------

    [Fact]
    public void Reg_export_is_read_in_utf16_utf8_and_cp1251()
    {
        var text = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Тест]\r\n\"Имя\"=\"Значение\"\r\n";
        var path = Path.Combine(Path.GetTempPath(), $"ufa-reg-{Guid.NewGuid():N}.reg");
        try
        {
            File.WriteAllBytes(path, [0xFF, 0xFE, .. Encoding.Unicode.GetBytes(text)]);
            Assert.Contains("Значение", RegExportParser.ReadAllText(path));

            File.WriteAllBytes(path, [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes(text)]);
            Assert.Contains("Значение", RegExportParser.ReadAllText(path));

            TextSanitizer.EnsureCodePagesRegistered();
            File.WriteAllBytes(path, Encoding.GetEncoding(1251).GetBytes(text));
            Assert.Contains("Значение", RegExportParser.ReadAllText(path));

            var keys = RegExportParser.ParseFile(path);
            Assert.Equal("Значение", Assert.Single(keys).GetString("Имя"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Reg_export_values_cover_every_supported_type()
    {
        var keys = RegExportParser.Parse(string.Join("\r\n",
        [
            "Windows Registry Editor Version 5.00",
            "",
            @"[HKEY_LOCAL_MACHINE\SYSTEM\Проба]",
            "@=\"по умолчанию\"",
            "\"строка\"=\"текст\"",
            "\"имя с \\\"=\\\" внутри\"=\"хитрое\"",
            "\"удалено\"=-",
            "\"число\"=dword:0000002a",
            "\"плохое число\"=dword:XYZ",
            "\"время\"=hex(b):d0,f9,c8,01,00,00,00,00",
            "\"короткое время\"=hex(b):01,02",
            "\"расширяемая\"=hex(2):43,00,3a,00,5c,00,00,00",
            "\"мультистрока\"=hex(7):61,00,00,00,62,00,00,00,00,00",
            "\"dword в hex\"=hex(4):2a,00,00,00",
            "\"байты\"=hex:de,ad,be,ef",
            "\"неизвестный hex\"=hex(9):01,02",
            "\"голый текст\"=просто текст",
            "строка мимо формата"
        ]));

        var key = Assert.Single(keys);
        Assert.Equal(@"HKEY_LOCAL_MACHINE\SYSTEM\Проба", key.Path);
        Assert.Equal("по умолчанию", key.GetString("@"));
        Assert.Equal("текст", key.GetString("строка"));
        Assert.Equal("хитрое", key.GetString("имя с \"=\" внутри"));
        Assert.True(key.Values.ContainsKey("удалено"));
        Assert.Null(key.Values["удалено"]);
        Assert.Equal(42u, key.Values["число"]);
        Assert.Null(key.Values["плохое число"]);
        Assert.IsType<ulong>(key.Values["время"]);
        Assert.IsType<byte[]>(key.Values["короткое время"]);
        Assert.Equal(@"C:\", key.GetString("расширяемая"));
        Assert.Equal(new[] { "a", "b" }, (string[])key.Values["мультистрока"]!);
        Assert.Equal(42u, key.Values["dword в hex"]);
        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, (byte[])key.Values["байты"]!);
        Assert.IsType<byte[]>(key.Values["неизвестный hex"]);
        Assert.Equal("просто текст", key.GetString("голый текст"));
    }

    // ---------- NetworkListParsers ----------

    [Theory]
    [InlineData(6, NetworkConnectionKind.Wired)]
    [InlineData(71, NetworkConnectionKind.WiFi)]
    [InlineData(23, NetworkConnectionKind.Vpn)]
    [InlineData(53, NetworkConnectionKind.Vpn)]
    [InlineData(131, NetworkConnectionKind.Vpn)]
    [InlineData(243, NetworkConnectionKind.MobileBroadband)]
    [InlineData(244, NetworkConnectionKind.MobileBroadband)]
    [InlineData(24, NetworkConnectionKind.Unknown)]
    [InlineData(999, NetworkConnectionKind.Unknown)]
    public void Interface_type_maps_to_connection_kind(int nameType, string expected)
    {
        var (kind, explanation) = NetworkListParsers.DescribeNameType(nameType);
        Assert.Equal(expected, kind);
        Assert.NotEmpty(explanation);
    }

    [Theory]
    [InlineData(0, "Общедоступная сеть")]
    [InlineData(1, "Частная сеть")]
    [InlineData(2, "Сеть домена")]
    [InlineData(7, "")]
    [InlineData(null, "")]
    public void Network_category_is_described(int? category, string expected)
    {
        Assert.Equal(expected, NetworkListParsers.DescribeCategory(category));
    }

    [Fact]
    public void Impossible_calendar_date_in_profile_returns_null()
    {
        // 30 февраля: SYSTEMTIME с корректными полями, но несуществующей датой.
        var bytes = SystemTime(2024, 2, 30);
        Assert.Null(NetworkListParsers.TryReadSystemTime(bytes));
    }

    [Theory]
    [InlineData("open", "открытая сеть без пароля", "none", "без шифрования")]
    [InlineData("shared", "общий ключ WEP", "WEP", "WEP")]
    [InlineData("WPA", "WPA-Enterprise", "TKIP", "TKIP")]
    [InlineData("WPA2", "WPA2-Enterprise", "AES", "AES")]
    [InlineData("WPA3", "WPA3-Enterprise", "GCMP256", "GCMP-256")]
    [InlineData("WPA3SAE", "WPA3-Personal", "AES", "AES")]
    [InlineData("нечто новое", "нечто новое", "шифр будущего", "шифр будущего")]
    public void Wlan_profile_authentication_and_encryption_are_translated(
        string auth, string expectedAuth, string encryption, string expectedEncryption)
    {
        var profile = NetworkListParsers.ParseWlanProfile(WlanProfileXml(auth, encryption, "manual"));

        Assert.NotNull(profile);
        Assert.Equal(expectedAuth, profile.Authentication);
        Assert.Equal(expectedEncryption, profile.Encryption);
    }

    [Fact]
    public void Wlan_profile_survives_broken_xml()
    {
        Assert.Null(NetworkListParsers.ParseWlanProfile("<не xml"));
        Assert.Null(NetworkListParsers.ParseWlanProfile(null));
        Assert.Null(NetworkListParsers.ParseWlanProfile(""));
    }

    // ---------- MulticastDnsProtocol ----------

    [Fact]
    public void Reverse_ptr_query_rejects_bad_addresses()
    {
        Assert.Empty(MulticastDnsProtocol.BuildReversePtrQuery("не адрес", 1));
        Assert.Empty(MulticastDnsProtocol.BuildReversePtrQuery("fe80::1", 1));
    }

    [Fact]
    public void Reverse_ptr_query_encodes_reversed_octets()
    {
        var packet = MulticastDnsProtocol.BuildReversePtrQuery("192.168.1.42", 0x1234);

        Assert.NotEmpty(packet);
        Assert.Equal(0x12, packet[0]);
        Assert.Equal(0x34, packet[1]);
        Assert.Contains("42.1.168.192.in-addr.arpa",
            Encoding.ASCII.GetString(packet));
    }

    [Fact]
    public void Ptr_response_with_compression_pointer_yields_host_name()
    {
        // Ответ с двумя записями: первая — TXT (должна быть пропущена), в её
        // данных лежит имя «printer.local»; вторая — PTR, данные которой
        // ссылаются на это имя указателем сжатия.
        var packet = new List<byte>
        {
            0x00, 0x00,             // transaction id = 0 — допустимо для mDNS
            0x84, 0x00,             // флаги: это ответ
            0x00, 0x00,             // QDCOUNT = 0
            0x00, 0x02,             // ANCOUNT = 2
            0x00, 0x00, 0x00, 0x00
        };

        // Запись 1: корневое имя, тип TXT, данные — полное имя printer.local.
        packet.Add(0x00);                                    // имя записи
        packet.AddRange([0x00, 0x10, 0x00, 0x01]);           // TXT, IN
        packet.AddRange([0x00, 0x00, 0x00, 0x78]);           // TTL
        var name = new List<byte> { 0x07 };
        name.AddRange(Encoding.ASCII.GetBytes("printer"));
        name.Add(0x05);
        name.AddRange(Encoding.ASCII.GetBytes("local"));
        name.Add(0x00);
        packet.AddRange([0x00, (byte)name.Count]);           // RDLENGTH
        var nameAt = packet.Count;                           // имя внутри данных
        packet.AddRange(name);

        // Запись 2: тип PTR, данные — указатель сжатия на имя из записи 1.
        packet.Add(0x00);
        packet.AddRange([0x00, 0x0C, 0x00, 0x01]);           // PTR, IN
        packet.AddRange([0x00, 0x00, 0x00, 0x78]);           // TTL
        packet.AddRange([0x00, 0x02]);                       // RDLENGTH = 2
        packet.AddRange([(byte)(0xC0 | (nameAt >> 8)), (byte)nameAt]);

        var host = MulticastDnsProtocol.ParsePtrResponse(packet.ToArray(), 0x0001);

        Assert.Equal("printer", host);
    }

    [Fact]
    public void Ptr_response_garbage_is_rejected()
    {
        Assert.Equal("", MulticastDnsProtocol.ParsePtrResponse(new byte[4], 1));
        // Запрос, а не ответ.
        var query = MulticastDnsProtocol.BuildReversePtrQuery("10.0.0.1", 7);
        Assert.Equal("", MulticastDnsProtocol.ParsePtrResponse(query, 7));
        // Ответ без записей.
        var empty = new byte[12];
        empty[2] = 0x84;
        Assert.Equal("", MulticastDnsProtocol.ParsePtrResponse(empty, 1));
    }

    // ---------- BluetoothServiceCatalog ----------

    [Theory]
    [InlineData(1, 3, "компьютер, ноутбук")]
    [InlineData(1, 6, "компьютер, планшет")]
    [InlineData(2, 3, "телефон, смартфон")]
    [InlineData(2, 4, "телефон, модем")]
    [InlineData(3, 0, "точка доступа в сеть")]
    [InlineData(4, 1, "звуковое устройство, гарнитура")]
    [InlineData(4, 6, "звуковое устройство, наушники")]
    [InlineData(5, 16, "клавиатура, мышь или игровой пульт, клавиатура")]
    [InlineData(5, 32, "клавиатура, мышь или игровой пульт, мышь")]
    [InlineData(6, 0, "камера или сканер")]
    [InlineData(7, 0, "часы или иное носимое устройство")]
    [InlineData(8, 0, "игрушка")]
    [InlineData(9, 0, "медицинское устройство")]
    [InlineData(15, 0, "устройство неизвестного вида")]
    public void Bluetooth_device_class_is_described(int major, int minor, string expected)
    {
        var classOfDevice = (major << 8) | (minor << 2);
        Assert.Equal(expected, BluetoothServiceCatalog.DescribeDeviceClass(classOfDevice));
    }

    [Fact]
    public void Bluetooth_service_bits_include_networking_and_transfer()
    {
        var withBits = (1 << 17) | (1 << 20) | (3 << 8);
        var services = BluetoothServiceCatalog.DescribeServiceClasses(withBits);

        Assert.Contains(services, x => x.Contains("сеть", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(BluetoothServiceCatalog.DescribeServiceClasses(null));
        Assert.Empty(BluetoothServiceCatalog.DescribeServiceClasses(0));
    }

    // ---------- NetworkEventValues ----------

    [Theory]
    [InlineData("0x00000000", "успешно")]
    [InlineData("0xC0000022", "доступ запрещён")]
    [InlineData("3221225506", "доступ запрещён")]
    [InlineData("-1073741790", "доступ запрещён")]
    [InlineData("0xC000006D", "не приняты имя или пароль")]
    [InlineData("0xC0000064", "такой учётной записи нет")]
    [InlineData("0xC00000CC", "такой сетевой папки на сервере нет")]
    [InlineData("0xC000014B", "соединение оборвано")]
    [InlineData("", "")]
    [InlineData("мусор", "")]
    public void Smb_status_codes_are_translated(string value, string expected)
    {
        Assert.Equal(expected, NetworkEventValues.DescribeStatus(value));
    }

    [Fact]
    public void Unknown_smb_status_stays_hexadecimal()
    {
        var described = NetworkEventValues.DescribeStatus("0xC0FFEE01");
        Assert.Contains("C0FFEE01", described, StringComparison.OrdinalIgnoreCase);
    }

    // ---------- DeviceKindResolver ----------

    [Theory]
    [InlineData(@"USBPRINT\HP_LaserJet\7&1", null, "Printer")]
    [InlineData(@"USBSER\COM3\6&2", null, "SerialPort")]
    [InlineData(@"HID\VID_046D&PID_C52B\5&3", null, "Input")]
    [InlineData(@"SWD\WPDBUSENUM\_??_USBSTOR", null, "PortableDevice")]
    [InlineData(@"SCSI\Disk&Ven_Samsung\4&1", "Internal NVMe", "Storage")]
    [InlineData(@"SCSI\Disk&Ven_Msft&Prod_Virtual_Disk\2&1", "Virtual Disk", "Storage")]
    [InlineData(@"ROOT\Неведомое\0000", null, "Unknown")]
    public void Instance_path_resolves_to_device_kind(string instanceId, string? transport, string expected)
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = instanceId, Transport = transport ?? "" };
        Assert.Equal(expected, DeviceKindResolver.Resolve(device));
    }

    [Fact]
    public void Every_device_kind_has_russian_description()
    {
        string[] kinds =
        [
            DeviceKindResolver.Storage, DeviceKindResolver.PortableDevice, "Camera", "Input",
            "Printer", "Audio", "Network", "SerialPort",
            DeviceKindResolver.Infrastructure, DeviceKindResolver.RegistryTrace, "Нечто"
        ];
        foreach (var kind in kinds)
        {
            Assert.NotEmpty(DeviceKindResolver.Describe(kind));
        }
        Assert.Equal("Назначение устройства определить не удалось", DeviceKindResolver.Describe("Нечто"));
    }

    [Theory]
    [InlineData("MSC/USBSTOR", null, "По USB как обычный диск")]
    [InlineData("UASP/SCSI", null, "По USB в скоростном режиме UASP")]
    [InlineData("MTP/PTP/WPD", null, "По USB в режиме передачи файлов (MTP/PTP), как телефон или камера")]
    [InlineData("USB", null, "По USB")]
    [InlineData("USB4/Thunderbolt/PCIe-tunneled candidate", null, "По USB4 или Thunderbolt")]
    [InlineData("Internal NVMe", null, "Внутренняя шина NVMe")]
    [InlineData("Internal Disk", null, "Внутренняя дисковая шина")]
    [InlineData("Virtual Disk", null, "Виртуальный диск гипервизора")]
    [InlineData(null, "USB", "По USB")]
    [InlineData(null, "USB4/Thunderbolt", "По USB4 или Thunderbolt")]
    [InlineData(null, "PCIe-tunneled candidate", "Возможно, через туннель PCIe (USB4/Thunderbolt)")]
    [InlineData(null, null, "Способ подключения определить не удалось")]
    public void Transport_is_described(string? transport, string? connection, string expected)
    {
        Assert.Equal(expected, DeviceKindResolver.DescribeTransport(transport, connection));
    }

    [Theory]
    [InlineData("External", "Внешнее, принесённое устройство")]
    [InlineData("BuiltIn", "Встроенное в машину")]
    [InlineData("Hub", "Часть шины, а не отдельное устройство")]
    [InlineData("Composite", "Интерфейс составного устройства")]
    [InlineData("Virtual", "Виртуальное, создано программой")]
    [InlineData("иное", "Происхождение определить не удалось")]
    public void Origin_is_described(string classification, string expected)
    {
        Assert.Equal(expected, DeviceKindResolver.DescribeOrigin(classification));
    }

    [Theory]
    [InlineData("High", "надёжно")]
    [InlineData("Medium", "с оговорками")]
    [InlineData("Low", "предположительно")]
    [InlineData(null, "без подтверждения")]
    public void Confidence_is_described(string? confidence, string expected)
    {
        Assert.Equal(expected, DeviceKindResolver.DescribeConfidence(confidence));
    }

    // ---------- NetworkVisitKind ----------

    [Fact]
    public void Visit_kinds_rank_folders_before_sites()
    {
        string[] ordered =
        [
            NetworkVisitKind.Folder, NetworkVisitKind.File, NetworkVisitKind.MappedDrive,
            NetworkVisitKind.TypedPath, NetworkVisitKind.RememberedShare,
            NetworkVisitKind.Download, NetworkVisitKind.Site, NetworkVisitKind.Host
        ];
        var ranks = ordered.Select(NetworkVisitKind.Rank).ToArray();
        Assert.Equal(ranks.OrderBy(x => x).ToArray(), ranks);
        Assert.True(NetworkVisitKind.Rank("нечто") > NetworkVisitKind.Rank(NetworkVisitKind.Host));
        Assert.Equal("Обращение определить не удалось", NetworkVisitKind.Describe("нечто"));
    }

    // ---------- ExternalUtilitySectionCatalog ----------

    [Fact]
    public void Section_titles_resolve_to_catalog_entries()
    {
        Assert.Equal(ExternalUtilitySectionCatalog.MainRegistrySection,
            ExternalUtilitySectionCatalog.GetInfo("Основной список из реестра").Title);
        Assert.Equal(ExternalUtilitySectionCatalog.OtherTracesSection,
            ExternalUtilitySectionCatalog.GetInfo("Другие следы подключения устройств").Title);
        Assert.Equal(ExternalUtilitySectionCatalog.DeviceListSection,
            ExternalUtilitySectionCatalog.GetInfo("Список устройств USBDeview").Title);
        Assert.True(ExternalUtilitySectionCatalog.IsOtherTracesSection("Другие следы чего-то"));
        Assert.False(ExternalUtilitySectionCatalog.IsOtherTracesSection("Основной список"));

        var generic = ExternalUtilitySectionCatalog.GetInfo("Никому не известная таблица");
        Assert.Equal("Никому не известная таблица", generic.Title);
        Assert.NotEmpty(generic.Summary);
    }

    private static byte[] SystemTime(int year, int month, int day)
    {
        var bytes = new byte[16];
        BitConverter.GetBytes((ushort)year).CopyTo(bytes, 0);
        BitConverter.GetBytes((ushort)month).CopyTo(bytes, 2);
        BitConverter.GetBytes((ushort)day).CopyTo(bytes, 6);
        return bytes;
    }

    private static string WlanProfileXml(string authentication, string encryption, string connectionMode) => $"""
        <?xml version="1.0"?>
        <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
          <name>Тестовая сеть</name>
          <SSIDConfig><SSID><name>Тестовая сеть</name></SSID></SSIDConfig>
          <connectionMode>{connectionMode}</connectionMode>
          <MSM><security>
            <authEncryption>
              <authentication>{authentication}</authentication>
              <encryption>{encryption}</encryption>
            </authEncryption>
            <sharedKey><keyMaterial>секрет</keyMaterial></sharedKey>
          </security></MSM>
        </WLANProfile>
        """;
}
