using System.Text.Json;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class UsbDeviceRecognitionTests
{
    private static UsbDeviceRecord Generic(string serial = "A") => new()
    {
        DeviceInstanceId = $@"USB\VID_0E0F&PID_0003\{serial}",
        FriendlyName = "USB Composite Device", Product = "USB Device",
        Serial = serial, Source = "Offline USB", Vid = "0E0F", Pid = "0003"
    };

    [Fact]
    public void Catalogue_hint_is_read_only_and_works_after_reload()
    {
        var device = Generic();
        var original = JsonSerializer.Serialize(device);
        Assert.Contains("Virtual Mouse", device.DisplayName);
        Assert.Contains("по VID/PID", device.ModelText);
        Assert.Contains("VMware", device.ManufacturerText);
        Assert.Contains("VID 0E0F / PID 0003", device.RecognitionEvidenceText);
        Assert.Equal(original, JsonSerializer.Serialize(device));
        Assert.Equal(device.DisplayName, JsonSerializer.Deserialize<UsbDeviceRecord>(original)!.DisplayName);
    }

    [Fact]
    public void Specific_windows_name_and_model_take_priority()
    {
        var device = Generic();
        device.FriendlyName = "My exact mouse";
        device.Product = "Specific model";
        Assert.Equal("My exact mouse", device.DisplayName);
        Assert.Equal("Specific model", device.ModelText);
        device.FriendlyName = "USB Device";
        Assert.Equal("Specific model", device.DisplayName);
        device.FriendlyName = "My exact mouse";
        device.Product = "USB Device";
        Assert.Equal("My exact mouse", device.ModelText);
    }

    [Fact]
    public void Hardware_ids_supply_a_hint_without_changing_identity()
    {
        var device = Generic();
        device.DeviceInstanceId = @"SWD\DEVICE\A";
        device.Vid = device.Pid = "";
        device.HardwareIds = "USB\\VID_0E0F&PID_0003&REV_0100; USB\\VID_0E0F&PID_0003";
        Assert.Contains("Virtual Mouse", device.ModelText);
        Assert.Equal("", device.Vid);
        Assert.Equal("", device.Pid);
    }

    [Theory]
    [InlineData("USB\\VID_0951&PID_1666")]
    [InlineData("USB\\VID_0E0F&PID_0003; USB\\VID_0951&PID_1666")]
    public void Conflicting_hardware_ids_block_catalogue_hint(string ids)
    {
        var device = Generic();
        device.HardwareIds = ids;
        Assert.False(UsbDeviceRecognition.Lookup(device).HasVendor);
        Assert.DoesNotContain("по VID/PID", device.ModelText);
    }

    [Fact]
    public void Conflicting_alias_or_explicit_code_blocks_hint()
    {
        var device = Generic();
        device.IdentityAliases.Add(@"USB\VID_0951&PID_1666\B");
        Assert.False(UsbDeviceRecognition.Lookup(device).HasProduct);
        device.IdentityAliases.Clear();
        device.Pid = "1666";
        Assert.False(UsbDeviceRecognition.Lookup(device).HasProduct);
    }

    [Fact]
    public void Bluetooth_codes_and_bare_serial_text_are_not_usb_models()
    {
        var device = Generic();
        device.DeviceInstanceId = @"BTHENUM\DEV_001122334455\A";
        Assert.False(UsbDeviceRecognition.Lookup(device).HasVendor);
        device.DeviceInstanceId = @"SWD\DEVICE\VID_0E0F&PID_0003";
        device.HardwareIds = "VID_0E0F&PID_0003";
        device.Vid = device.Pid = "";
        Assert.False(UsbDeviceRecognition.Lookup(device).HasVendor);
    }

    [Fact]
    public void Vendor_only_and_unknown_product_do_not_invent_model()
    {
        var device = new UsbDeviceRecord { Vid = "0E0F", Pid = "FFFF" };
        Assert.Contains("VMware", device.ManufacturerText);
        Assert.DoesNotContain("по VID/PID", device.ModelText);
        Assert.False(UsbDeviceRecognition.Lookup(device).HasProduct);
    }

    [Fact]
    public void Live_view_uses_same_hints()
    {
        var device = new LiveUsbDevice
        {
            DeviceId = @"USB\VID_0E0F&PID_0003\A", DeviceName = "USB Composite Device"
        };
        Assert.Contains("Virtual Mouse", device.DisplayName);
        Assert.Contains("Virtual Mouse", device.ModelText);
        Assert.Equal("USB Composite Device", device.DeviceName);
    }

    [Fact]
    public void Same_model_does_not_merge_distinct_physical_devices()
    {
        var first = Generic("A");
        var second = Generic("B");
        DeviceIdentityGraph.Process(new List<UsbDeviceRecord> { first, second });
        Assert.NotEqual(first.CanonicalDeviceId, second.CanonicalDeviceId);
        Assert.Equal(first.DisplayName, second.DisplayName);
    }
}
