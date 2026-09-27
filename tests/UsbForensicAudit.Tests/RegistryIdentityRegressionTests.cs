using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class RegistryIdentityRegressionTests
{
    [Theory]
    [InlineData("{00000000-0000-0000-0000-000000000000}")]
    [InlineData("{00000000-0000-0000-ffff-ffffffffffff}")]
    [InlineData("{A}")]
    public void Placeholder_containers_never_link_registry_records(string container) =>
        Assert.False(UsbRegistryForensicHelpers.IdentitiesCorrelate(new() { ContainerId = container }, new() { ContainerId = container }));

    [Fact]
    public void Reused_serial_of_different_models_does_not_link_portable_records() =>
        Assert.False(UsbRegistryForensicHelpers.IdentitiesCorrelate(
            new() { Serial = "SERIAL-123", Vid = "1234", Pid = "5678" },
            new() { Serial = "SERIAL-123", Vid = "4321", Pid = "8765" }));

    [Theory]
    [InlineData("1234567890", "123456789")]
    [InlineData("6&1234abcd&0", "6&1234abcd&0")]
    public void Substring_and_generated_serials_do_not_supply_vid_pid(string storageSerial, string usbSerial)
    {
        var storage = new UsbDeviceRecord { Source = "Registry: USBSTOR", DeviceInstanceId = @"USBSTOR\Disk&Ven_Test\" + storageSerial, Serial = storageSerial };
        var usb = new UsbDeviceRecord { Source = "Registry: USB", DeviceInstanceId = @"USB\VID_1234&PID_5678\" + usbSerial, Serial = usbSerial, Vid = "1234", Pid = "5678" };
        UsbRegistryCollector.EnrichUsbStorVidPid([storage, usb]);
        Assert.Empty(storage.Vid);
        Assert.Empty(storage.Pid);
    }

    [Fact]
    public void Exact_parent_prefix_supplies_vid_pid_to_a_generated_storage_instance()
    {
        var storage = new UsbDeviceRecord { Source = "Registry: USBSTOR", DeviceInstanceId = @"USBSTOR\Disk&Ven_Test\6&1234ABCD&0&0" };
        var usb = new UsbDeviceRecord { Source = "Registry: USB", DeviceInstanceId = @"USB\VID_1234&PID_5678\5&4567&0&1", ParentIdPrefix = "6&1234ABCD&0", Vid = "1234", Pid = "5678" };
        UsbRegistryCollector.EnrichUsbStorVidPid([storage, usb]);
        Assert.Equal("1234", storage.Vid);
        Assert.Equal("5678", storage.Pid);
    }

    [Fact]
    public void Ambiguous_serial_does_not_choose_the_first_usb_model()
    {
        var storage = new UsbDeviceRecord { Source = "Registry: USBSTOR", Serial = "SERIAL-123" };
        var portable = new UsbDeviceRecord { Source = "Registry: Portable Devices", Serial = "SERIAL-123" };
        var first = new UsbDeviceRecord { Source = "Registry: USB", Serial = "SERIAL-123", Vid = "1234", Pid = "5678" };
        var second = new UsbDeviceRecord { Source = "Registry: USB", Serial = "SERIAL-123", Vid = "4321", Pid = "8765" };
        UsbRegistryCollector.CorrelatePortableDevices([portable, first, second]);
        UsbRegistryCollector.EnrichUsbStorVidPid([storage, first, second]);
        Assert.Empty(portable.Vid);
        Assert.Empty(storage.Vid);
        Assert.Empty(portable.ContainerId);
    }

    [Fact]
    public void Wpd_backing_id_links_without_vid_pid_serial_or_container()
    {
        const string id = @"USBSTOR\DISK&VEN_TEST\6&1234ABCD&0";
        Assert.True(UsbRegistryForensicHelpers.IdentitiesCorrelate(new() { DeviceInstanceId = @"SWD\WPDBUSENUM\_??_" + id },
            new() { DeviceInstanceId = id }));
    }
}
