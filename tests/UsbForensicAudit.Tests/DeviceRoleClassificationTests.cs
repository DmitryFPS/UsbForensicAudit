using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Роль устройства определяется по тому, чем устройство является, а не по тому,
/// куда оно воткнуто. Windows пишет каждому устройству строку размещения вида
/// "Port_#0008.Hub_#0001", и пока она участвовала в разборе признаков, флешки и
/// телефоны получали роль концентратора и уходили из счётчика устройств.
/// </summary>
public class DeviceRoleClassificationTests
{
    [Fact]
    public void Flash_drive_plugged_into_a_hub_is_not_a_hub()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            Source = "Registry: USBSTOR",
            Service = "disk",
            HardwareIds = @"USBSTOR\DiskGeneral_UDisk___________5.00",
            CompatibleIds = @"USBSTOR\Disk; USBSTOR\RAW; GenDisk",
            LocationInformation = "Port_#0008.Hub_#0001",
            FriendlyName = "General UDisk USB Device"
        };

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("External", device.Classification);
        Assert.Equal("Storage", device.DeviceKind);
    }

    [Fact]
    public void Phone_plugged_into_a_hub_is_not_a_hub()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_2717&PID_FF40\8dde262e",
            Source = "Registry: USB; Registry: Portable Devices",
            DeviceType = "Portable/MTP",
            LocationInformation = "Port_#0007.Hub_#0001",
            FriendlyName = "POCO X3 NFC",
            Manufacturer = "Xiaomi"
        };

        DeviceTransportClassifier.Classify(device);

        Assert.NotEqual("Hub", device.Classification);
        Assert.Equal("PortableDevice", device.DeviceKind);
    }

    [Fact]
    public void Location_string_inside_the_raw_registry_dump_does_not_make_a_hub_either()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_ABCD&PID_1234\2412242109410569603146",
            Source = "Registry: USB",
            Service = "USBSTOR",
            FriendlyName = "USB Mass Storage Device",
            RawJson = """{"Values":{"LocationInformation":"Port_#0008.Hub_#0001"}}"""
        };

        DeviceTransportClassifier.Classify(device);

        Assert.NotEqual("Hub", device.Classification);
    }

    [Fact]
    public void Real_hub_is_still_recognised_by_its_own_evidence()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_05E3&PID_0608\5&2b7e5f4&0&2",
            Source = "Registry: USB",
            Service = "USBHUB3",
            CompatibleIds = @"USB\Class_09&SubClass_00&Prot_01; USB\Class_09",
            LocationInformation = "Port_#0002.Hub_#0001",
            FriendlyName = "Generic USB Hub"
        };

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("Hub", device.Classification);
    }

    [Fact]
    public void Root_hub_is_still_recognised_by_its_instance_id()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\ROOT_HUB30\4&2dda3b82&0&0",
            Source = "Registry: USB",
            FriendlyName = "Корневой USB-концентратор (USB 3.0)"
        };

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("Hub", device.Classification);
    }
}
