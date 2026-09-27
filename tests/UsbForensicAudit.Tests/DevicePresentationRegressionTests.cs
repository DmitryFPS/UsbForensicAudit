using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DevicePresentationRegressionTests
{
    [Theory]
    [InlineData(@"USB\VID_174C&PID_A89A\MSFT302N152922J9C9", "174C", "A89A")]
    [InlineData(@"##?#USB#vid_346d&pid_5678#SERIAL#{11111111-2222-3333-4444-555555555555}", "346D", "5678")]
    [InlineData(@"SWD\WPDBUSENUM\_??_USB#VID_174C&PID_A89A#SERIAL", "174C", "A89A")]
    [InlineData(@"HID\VID_1234&PID_5678&MI_00\6&ABC&0&1", "1234", "5678")]
    public void Codes_are_recovered_from_actual_device_identifiers(string id, string vid, string pid)
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = id };
        DeviceIdentifierMetadata.FillMissingCodes(device);
        Assert.Equal(vid, device.Vid);
        Assert.Equal(pid, device.Pid);
    }

    [Theory]
    [InlineData("aUSB\\VID_174C&PID_A89A\\SERIAL")]
    [InlineData("USB\\VID_174C&PID_A89AB\\SERIAL")]
    [InlineData("USB\\VID_174&PID_A89A\\SERIAL")]
    [InlineData("USBSTOR\\Disk&Ven_VID_174C&PID_A89A\\SERIAL")]
    public void Similar_text_does_not_supply_vid_pid(string id) => Assert.Null(DeviceIdentifierMetadata.Pair(id));

    [Fact]
    public void Conflicting_aliases_or_existing_codes_are_not_overwritten()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_174C&PID_A89A\SERIAL", Vid = "9999" };
        DeviceIdentifierMetadata.FillMissingCodes(device);
        Assert.Equal("9999", device.Vid);
        Assert.Empty(device.Pid);
        device.Vid = "";
        device.IdentityAliases = [@"USB\VID_1234&PID_5678\OTHER"];
        DeviceIdentifierMetadata.FillMissingCodes(device);
        Assert.Empty(device.Vid);
        device.DeviceInstanceId = @"SWD\WPDBUSENUM\WRAPPER";
        device.Pid = "0000";
        DeviceIdentifierMetadata.FillMissingCodes(device);
        Assert.Empty(device.Vid);
        device.Pid = "5678";
        DeviceIdentifierMetadata.FillMissingCodes(device);
        Assert.Equal("1234", device.Vid);
    }

    [Fact]
    public void Asmedia_interface_trace_has_readable_fallback_without_inventing_a_model()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_174C&PID_A89A\MSFT302N152922J9C9",
            Source = "Registry: DeviceClasses",
            RawJson = "original"
        };
        DeviceIdentityGraph.Process([device]);
        Assert.Equal("174C", device.Vid);
        Assert.Equal("A89A", device.Pid);
        Assert.StartsWith("USB-устройство", device.DisplayName);
        Assert.Contains("модель неизвестна", device.DisplayName);
        Assert.DoesNotContain("USB\\", device.DisplayName);
        Assert.Empty(device.FriendlyName);
        Assert.Equal("original", device.RawJson);
    }

    [Theory]
    [InlineData(@"##?#USB#VID_1234&PID_5678#SERIAL", "USB", "")]
    [InlineData(@"HID\VID_1234&PID_5678\SERIAL", "", "")]
    [InlineData(@"SCSI\Disk&Ven_Test\SERIAL", "UASP/SCSI", DeviceKindResolver.Storage)]
    public void Technical_names_in_related_usb_transports_have_a_readable_fallback(string id, string transport, string kind)
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = id, Transport = transport, DeviceKind = kind };
        Assert.Contains("модель неизвестна", device.DisplayName);
        Assert.DoesNotContain('\\', device.DisplayName);
    }

    [Fact]
    public void Unnamed_usbflags_trace_displays_its_purpose_instead_of_a_registry_path()
    {
        var trace = new UsbDeviceRecord { DeviceInstanceId = @"HKLM\SYSTEM\ControlSet001\Control\usbflags\346D56780200", DeviceType = "USBFlags" };
        Assert.Equal("Кэш USB-дескрипторов", trace.DisplayName);
        trace.DeviceType = "";
        trace.Source = "Registry: usbflags";
        Assert.Equal("Кэш USB-дескрипторов", trace.DisplayName);
    }

    [Theory]
    [InlineData("USB")]
    [InlineData("USB Device")]
    [InlineData("USB-устройство")]
    public void Generic_usb_name_does_not_hide_device_kind_or_survive_as_group_name(string name)
    {
        var device = new UsbDeviceRecord
        {
            FriendlyName = name,
            DeviceKind = DeviceKindResolver.Storage,
            DeviceInstanceId = @"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_Test#SERIAL&0",
            GroupDisplayName = "USB"
        };
        DeviceIdentityGraph.Process([device]);
        Assert.Equal("USB-накопитель (модель неизвестна)", device.DisplayName);
        Assert.Equal(name, device.FriendlyName);
        Assert.True(DeviceNameQuality.IsClassName(device.DisplayName));
        device.Product = "Real Model";
        Assert.Equal("Real Model", device.DisplayName);
    }

    [Fact]
    public void Generic_name_can_borrow_real_model_only_from_the_same_device()
    {
        var main = new UsbDeviceRecord { FriendlyName = "USB", DeviceInstanceId = @"USB\VID_1234&PID_5678\SERIAL", VisualCategory = "RealUsb" };
        var disk = new UsbDeviceRecord { FriendlyName = "Real Model", DeviceInstanceId = @"USBSTOR\Disk&Ven_Test\SERIAL&0", IdentityAliases = [main.DeviceInstanceId] };
        DeviceIdentityGraph.Process([main, disk]);
        Assert.Equal("Real Model", main.DisplayName);
        Assert.Equal("USB", main.FriendlyName);
        DeviceIdentityGraph.Process([main]);
        Assert.Contains("модель неизвестна", main.DisplayName);
    }

    [Fact]
    public void Encoded_and_decoded_orphan_wrappers_link_by_exact_backing_id_without_serial_field()
    {
        var wpd = new UsbDeviceRecord { DeviceInstanceId = @"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_Test#6&ABCDEF&0&0000" };
        var volume = new UsbDeviceRecord { DeviceInstanceId = @"STORAGE\Volume\_??_USBSTOR#Disk&Ven_Test#6&ABCDEF&0&0000#{11111111-2222-3333-4444-555555555555}" };
        var other = new UsbDeviceRecord { DeviceInstanceId = @"STORAGE\Volume\_??_USBSTOR#Disk&Ven_Test#6&ABCDEF&0&0001" };
        DeviceIdentityGraph.Process([wpd, volume, other]);
        Assert.Equal(wpd.CanonicalDeviceId, volume.CanonicalDeviceId);
        Assert.NotEqual(wpd.CanonicalDeviceId, other.CanonicalDeviceId);
        Assert.Equal("High", wpd.IdentityConfidence);
        Assert.Contains(wpd.IdentityProvenance, x => x.StartsWith("ExactDeviceReference:"));
    }

    [Fact]
    public void Group_search_matches_components_and_keeps_complete_physical_group()
    {
        var main = new UsbDeviceRecord { CanonicalDeviceId = "A", IsCanonicalPrimary = true, FriendlyName = "Camera", Classification = "External", ClassificationConfidence = "High" };
        var child = new UsbDeviceRecord { CanonicalDeviceId = "A", Serial = "SERIAL123", Transport = "MTP/PTP/WPD" };
        var hidden = new UsbDeviceRecord { DeviceType = "VolumeLabel", FriendlyName = "Camera" };
        var other = new UsbDeviceRecord { CanonicalDeviceId = "B", IsCanonicalPrimary = true, FriendlyName = "Different camera" };
        var records = new[] { main, child, hidden, other };
        Assert.Equal(2, DeviceListPresentation.Select(records, false, "Camera SERIAL123").Count);
        Assert.Equal(2, DeviceListPresentation.Select(records, false, "SERIAL123", "ExternalOnly").Count);
        Assert.Equal(2, DeviceListPresentation.Select(records, false, "Camera", "MTP/PTP/WPD").Count);
        Assert.Empty(DeviceListPresentation.Select(records, false, "Camera", "ExternalMedia"));
        Assert.Equal(4, DeviceListPresentation.Select(records, true, "").Count);
        Assert.Equal(3, DeviceListPresentation.Select(records, false, "").Count);
        Assert.NotEqual(DeviceListPresentation.GroupKey(new()), DeviceListPresentation.GroupKey(new()));
        Assert.Equal(DeviceListPresentation.GroupKey(new() { DeviceInstanceId = @"usb\vid_1234&pid_5678\one" }),
            DeviceListPresentation.GroupKey(new() { DeviceInstanceId = @"USB\VID_1234&PID_5678\ONE" }));
    }
}
