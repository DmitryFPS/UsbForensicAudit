using System.Globalization;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceIdentityBoundaryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Conflicting_devices_on_shared_topology_never_get_the_same_canonical_id(bool reverse)
    {
        var first = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_1111&PID_2222\5&ABC&0&1", ParentIdPrefix = "6&ABC&0", LocationPaths = "PORT1" };
        var second = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_3333&PID_4444\5&ABC&0&1", ParentIdPrefix = "6&ABC&0", LocationPaths = "PORT1" };
        UsbDeviceRecord[] records = reverse ? [second, first] : [first, second];
        DeviceIdentityGraph.Process(records);
        Assert.NotEqual(first.CanonicalDeviceId, second.CanonicalDeviceId);
        Assert.All(records, x => Assert.True(x.IsCanonicalPrimary));
        Assert.Single(DeviceListPresentation.Select(records, false, "VID_1111"));
    }

    [Fact]
    public void Port_location_alone_does_not_link_generated_instances_of_the_same_model()
    {
        var first = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_05E3&PID_0751\5&ABC&0&8", LocationPaths = "PORT1" };
        var second = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_05E3&PID_0751\5&ABC&0&10", LocationPaths = "PORT1" };
        DeviceIdentityGraph.Process([first, second]);
        Assert.NotEqual(first.CanonicalDeviceId, second.CanonicalDeviceId);
        Assert.NotEqual(first.InstanceSummary, second.InstanceSummary);
    }

    [Fact]
    public void Anonymous_records_from_same_source_remain_independent()
    {
        var records = new[] { new UsbDeviceRecord { Source = "same" }, new UsbDeviceRecord { Source = "same" } };
        DeviceIdentityGraph.Process(records);
        Assert.NotEqual(records[0].CanonicalDeviceId, records[1].CanonicalDeviceId);
    }

    [Fact]
    public void Parent_relation_connects_samsung_interfaces_and_model_cache_without_merging_bluetooth_by_name()
    {
        const string name = "Galaxy S9+ пользователя Дмитрий";
        var usb = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_04E8&PID_6860\1CB942B917047ECE", FriendlyName = name, Serial = "1CB942B917047ECE" };
        var mi0 = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_04E8&PID_6860&MI_00\6&1113778F&0&0000", FriendlyName = name, ParentDeviceInstanceId = usb.DeviceInstanceId };
        var mi4 = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_04E8&PID_6860&MI_04\6&1113778F&0&0004" };
        var cache = new UsbDeviceRecord { DeviceInstanceId = @"HKLM\SYSTEM\ControlSet001\Control\usbflags\04E868600C00", Vid = "04E8", Pid = "6860", Source = "Registry: usbflags" };
        var bt = new UsbDeviceRecord { DeviceInstanceId = @"BTHENUM\Dev_887598C2F5F2\7&ABC&0&BluetoothDevice_887598C2F5F2", FriendlyName = name };
        UsbDeviceRecord[] devices = [usb, mi0, mi4, cache, bt];
        DeviceIdentityGraph.Process(devices);
        Assert.All(devices.Take(4), x => Assert.Equal(usb.CanonicalDeviceId, x.CanonicalDeviceId));
        Assert.NotEqual(usb.CanonicalDeviceId, bt.CanonicalDeviceId);
        Assert.Contains(mi0.IdentityProvenance, x => x.StartsWith("ParentDevice:"));
        Assert.Equal(4, DeviceListPresentation.Select(devices, false, "1CB942B917047ECE").Count);
    }

    [Fact]
    public void Explicit_parent_of_another_model_or_a_hub_does_not_link_devices()
    {
        var hub = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_1234&PID_5678\HUB", Service = "USBHUB3" };
        var child = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_1234&PID_5678&MI_00\6&ABC&0&0000", ParentDeviceInstanceId = hub.DeviceInstanceId };
        DeviceIdentityGraph.Process([hub, child]);
        Assert.NotEqual(hub.CanonicalDeviceId, child.CanonicalDeviceId);
        hub.Service = "";
        hub.DeviceInstanceId = @"USB\VID_9999&PID_5678\HUB";
        child.ParentDeviceInstanceId = hub.DeviceInstanceId;
        DeviceIdentityGraph.Process([hub, child]);
        Assert.NotEqual(hub.CanonicalDeviceId, child.CanonicalDeviceId);
    }

    [Fact]
    public void Bluetooth_classic_and_le_join_by_remote_address_even_with_different_containers()
    {
        var bt = new UsbDeviceRecord { DeviceInstanceId = @"BTHENUM\Dev_887598C2F5F2\7&ABC&0&BluetoothDevice_887598C2F5F2", ContainerId = "82e332c1-0e1a-5123-843d-132f3a51b2f8", FriendlyName = "Phone" };
        var le = new UsbDeviceRecord { DeviceInstanceId = @"BTHLEDEVICE\{00001800-0000-1000-8000-00805f9b34fb}_887598c2f5f2\8&ABC&0&0014", ContainerId = "13bb1b83-5b34-591d-a3d0-a4adb9358d15" };
        var service = new UsbDeviceRecord { DeviceInstanceId = @"BTHENUM\{00001105-0000-1000-8000-00805f9b34fb}_VID&00010075_PID&0100\7&ABC&0&887598C2F5F2_C00000000" };
        var other = new UsbDeviceRecord { DeviceInstanceId = @"BTHENUM\Dev_112233445566\7&ABC&0&BluetoothDevice_112233445566", FriendlyName = "Phone" };
        DeviceIdentityGraph.Process([bt, le, service, other]);
        Assert.Equal(bt.CanonicalDeviceId, le.CanonicalDeviceId);
        Assert.Equal(bt.CanonicalDeviceId, service.CanonicalDeviceId);
        Assert.NotEqual(bt.CanonicalDeviceId, other.CanonicalDeviceId);
        Assert.Contains(bt.IdentityProvenance, x => x.StartsWith("BluetoothAddress:"));
        Assert.True(DeviceSearch.Matches([bt, le, service], "88:75:98:C2:F5:F2"));
    }

    [Theory]
    [InlineData(@"USB\Dev_887598C2F5F2\SERIAL")]
    [InlineData(@"BTHENUM\Dev_000000000000\INSTANCE")]
    [InlineData(@"BTHENUM\Dev_FFFFFFFFFFFF\INSTANCE")]
    [InlineData(@"BTHLEDEVICE\{00001800-0000-1000-8000-00805f9b34fb}_887598c2f5f20\INSTANCE")]
    public void Bluetooth_address_parser_rejects_non_addresses(string id) => Assert.Empty(BluetoothEnumeratorId.DeviceAddress(id));

    [Fact]
    public void Same_named_flash_drives_get_distinct_headers_and_keep_search_and_selection_separate()
    {
        UsbDeviceRecord[] devices = [new() { FriendlyName = "JINNLIVEUSB", DeviceInstanceId = @"USB\VID_ABCD&PID_1234\2412242109410569603146", Serial = "2412242109410569603146" },
            new() { DeviceInstanceId = @"USBSTOR\Disk&Ven_General\2412242109410569603146&0", Serial = "2412242109410569603146" },
            new() { FriendlyName = "JINNLIVEUSB", DeviceInstanceId = @"USB\VID_ABCD&PID_1234\2412281911546114543745", Serial = "2412281911546114543745" },
            new() { DeviceInstanceId = @"USBSTOR\Disk&Ven_General\2412281911546114543745&0", Serial = "2412281911546114543745" }];
        DeviceIdentityGraph.Process(devices);
        var grouping = new DevicePhysicalGrouping();
        grouping.Reset(devices);
        var first = (DeviceDisplayGroup)grouping.GroupNameFromItem(devices[0], 0, CultureInfo.InvariantCulture);
        var second = (DeviceDisplayGroup)grouping.GroupNameFromItem(devices[2], 0, CultureInfo.InvariantCulture);
        Assert.NotEqual(first.Title, second.Title);
        Assert.Contains("2412242109410569603146", first.Title);
        Assert.Contains("2412281911546114543745", second.Title);
        grouping.UpdateSelection(first.Items);
        Assert.True(first.IsSelected);
        Assert.False(second.IsSelected);
        Assert.Equal(2, DeviceListPresentation.Select(devices, false, "JINNLIVEUSB 2412242109410569603146").Count);
    }

    [Theory]
    [InlineData("##?#USB#VID_05E3&PID_0751#5&393A40CE&0&8", "5&393A40CE&0&8")]
    [InlineData("##?#USB#VID_04E8&PID_6860&MI_00#6&1113778F&0&0000", "6&1113778F&0&0000")]
    [InlineData("USBSTOR#Disk&Ven_Generic#6&2cb3244f&1", "6&2cb3244f&1")]
    [InlineData("USBSTOR#Disk&Ven_Test#SERIAL123&0", "SERIAL123")]
    public void Registry_parser_preserves_generated_instance_suffixes(string path, string expected)
        => Assert.Equal(expected, UsbRegistryForensicHelpers.ParseWpdIdentity(path).Serial);
}
