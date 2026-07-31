using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class RegExportParserTests
{
    private const string Export = """
        Windows Registry Editor Version 5.00

        ; экспорт с исследуемой машины
        [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0]
        "DeviceDesc"="@disk.inf,%disk_devdesc%;Дисковый накопитель"
        "FriendlyName"="General UDisk USB Device"
        "Service"="disk"
        "ContainerID"="{c8fa1c9a-7e42-5a44-9c1a-1d2e3f405162}"
        "HardwareID"=hex(7):55,00,53,00,42,00,53,00,54,00,4f,00,52,00,5c,00,44,00,69,00,\
          73,00,6b,00,00,00,00,00
        "ConfigFlags"=dword:00000000

        [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0\Device Parameters]
        "Partmgr"=dword:00000001

        [HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices]
        "\\DosDevices\\E:"=hex:5f,00,3f,00,3f,00,5f,00

        [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_2717&PID_FF40\8dde262e]
        "DeviceDesc"="POCO M6 Pro"
        "Mfg"="Xiaomi"
        """;

    [Fact]
    public void Sections_and_typed_values_are_read()
    {
        var keys = RegExportParser.Parse(Export);

        var disk = Assert.Single(keys, x => x.Path.EndsWith(@"2412242109410569603146&0", StringComparison.Ordinal));
        Assert.Equal("General UDisk USB Device", disk.GetString("FriendlyName"));
        Assert.Equal("disk", disk.GetString("Service"));
        Assert.Equal("{c8fa1c9a-7e42-5a44-9c1a-1d2e3f405162}", disk.GetString("ContainerID"));
        Assert.Equal(0u, disk.Values["ConfigFlags"]);
    }

    [Fact]
    public void Multi_string_value_split_across_lines_is_joined()
    {
        var disk = RegExportParser.Parse(Export)
            .Single(x => x.Path.EndsWith(@"2412242109410569603146&0", StringComparison.Ordinal));

        var hardwareIds = Assert.IsType<string[]>(disk.Values["HardwareID"]);
        Assert.Contains(@"USBSTOR\Disk", hardwareIds);
    }

    [Fact]
    public void Escaped_backslashes_in_value_names_and_text_are_unescaped()
    {
        var mounted = RegExportParser.Parse(Export)
            .Single(x => x.Path.EndsWith("MountedDevices", StringComparison.Ordinal));

        Assert.True(mounted.Values.ContainsKey(@"\DosDevices\E:"));
        Assert.Equal("_??_", System.Text.Encoding.Unicode.GetString(mounted.GetBinary(@"\DosDevices\E:")!));
    }

    [Fact]
    public void Comment_lines_are_ignored()
    {
        Assert.DoesNotContain(RegExportParser.Parse(Export), x => x.Path.StartsWith(';'));
    }

    [Fact]
    public void Devices_are_built_from_the_export_without_service_subkeys()
    {
        var records = OfflineRegExportCollector.Build(RegExportParser.Parse(Export));

        Assert.DoesNotContain(records, x => x.DeviceInstanceId.EndsWith("Device Parameters", StringComparison.Ordinal));
        Assert.Contains(records, x => x.Serial == "2412242109410569603146&0");

        var phone = Assert.Single(records, x => x.Vid == "2717");
        Assert.Equal("FF40", phone.Pid);
        Assert.Equal("POCO M6 Pro", phone.Product);
    }

    [Fact]
    public void Offline_records_state_that_dates_cannot_be_established()
    {
        var records = OfflineRegExportCollector.Build(RegExportParser.Parse(Export));

        Assert.All(records, record =>
        {
            Assert.Null(record.FirstConnectedUtc);
            Assert.Contains("дату подключения", record.DateConfidence, StringComparison.Ordinal);
        });
    }
}
