using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Ветка DeviceClasses перечисляет интерфейсы всех устройств Windows, включая
/// чисто программные: очереди печати, звуковые точки, VPN-минипорты. Во вкладку
/// устройств должны попадать только интерфейсы, за которыми стоит носитель или
/// телефон, и склеиваться они должны с физической записью, а не висеть отдельно.
/// </summary>
public class DeviceInterfaceArrivalTests
{
    [Theory]
    [InlineData(@"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0", true)]
    [InlineData(@"USB\VID_2717&PID_FF40\8dde262e", true)]
    [InlineData(@"SWD\WPDBUSENUM\_??_USBSTOR\Disk&Ven_General&Prod_UDisk\2412&0", true)]
    [InlineData(@"SD\Card\1234", true)]
    [InlineData(@"BTHENUM\{0000110a-0000-1000-8000-00805f9b34fb}\7&1a2b", true)]
    [InlineData(@"SWD\PRINTENUM\{F1242019-3FE0-4042-876C-7AA6F60BC5FF}", false)]
    [InlineData(@"SWD\MMDEVAPI\{0.0.0.00000000}.{de82a927-d9d2-48fc-9813-8a88002e9fa7}", false)]
    [InlineData(@"SWD\MSRRAS\MS_PPTPMINIPORT", false)]
    [InlineData(@"SWD\Wintun\{32669C6A-DFF8-6869-6E20-54CCB337AF1D}", false)]
    [InlineData(@"SWD\RADIO\Bluetooth_9010576eda10", false)]
    [InlineData(@"SWD\DRIVERENUM\IpfEfExtComponent&4&14bc8b6&0", false)]
    [InlineData(@"BTH\MS_RFCOMM\6&2372791f&0&0", false)]
    [InlineData(@"BTH\MS_BTHPAN\6&2372791f&0&2", false)]
    public void Only_interfaces_backed_by_removable_hardware_become_device_records(string instanceId, bool expected)
    {
        Assert.Equal(expected, UsbRegistryCollector.LooksLikeRemovableInterface(instanceId));
    }

    [Fact]
    public void Wpd_interface_key_with_two_trailing_guids_yields_the_real_serial()
    {
        const string symbolicLink =
            "##?#SWD#WPDBUSENUM#_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00"
            + "#2412242109410569603146&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
            + "#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";

        var identity = UsbRegistryForensicHelpers.ParseWpdIdentity(symbolicLink);

        Assert.Equal("2412242109410569603146", identity.Serial);
        Assert.DoesNotContain("{", identity.DeviceInstanceId, StringComparison.Ordinal);
        Assert.Equal(
            @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            identity.BackingDeviceInstanceId);
    }

    [Fact]
    public void Plain_usbstor_interface_key_still_parses_as_before()
    {
        const string symbolicLink =
            "##?#USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00"
            + "#2412242109410569603146&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";

        var identity = UsbRegistryForensicHelpers.ParseWpdIdentity(symbolicLink);

        Assert.Equal("2412242109410569603146", identity.Serial);
        Assert.StartsWith(@"USBSTOR\Disk", identity.DeviceInstanceId, StringComparison.Ordinal);
    }

    [Fact]
    public void Interface_record_merges_with_its_physical_device_through_the_alias()
    {
        var physical = new UsbDeviceRecord
        {
            Source = "Registry: USBSTOR",
            DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            Serial = "2412242109410569603146&0"
        };
        var arrival = new UsbDeviceRecord
        {
            Source = "Registry: DeviceClasses",
            DeviceType = "DeviceInterface",
            DeviceInstanceId = @"SWD\WPDBUSENUM\_??_USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            IdentityAliases = [@"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0"]
        };

        var devices = new List<UsbDeviceRecord> { physical, arrival };
        DeviceIdentityGraph.Process(devices);

        Assert.Equal(physical.CanonicalDeviceId, arrival.CanonicalDeviceId);
    }

    [Fact]
    public void Orphan_interface_record_is_presented_as_a_registry_trace()
    {
        var record = new UsbDeviceRecord
        {
            DeviceType = "DeviceInterface",
            DeviceInstanceId = @"SD\Card\1234",
            Transport = "Unknown"
        };

        Assert.Equal(DeviceKindResolver.RegistryTrace, DeviceKindResolver.Resolve(record));
    }

    [Fact]
    public void Interface_of_a_flash_drive_keeps_its_storage_kind()
    {
        var record = new UsbDeviceRecord
        {
            DeviceType = "DeviceInterface",
            DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412&0",
            Transport = "MSC/USBSTOR"
        };

        Assert.Equal(DeviceKindResolver.Storage, DeviceKindResolver.Resolve(record));
    }
}
