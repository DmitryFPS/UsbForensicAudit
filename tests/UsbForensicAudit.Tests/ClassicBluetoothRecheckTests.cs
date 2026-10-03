using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class ClassicBluetoothRecheckTests
{
    private const string Address = "887598C2F5F2";
    private const string Phone = @"BTHENUM\Dev_887598C2F5F2\7&2768a9f8&0&BluetoothDevice_887598C2F5F2";

    private static ClassicBluetoothSnapshot Snapshot(bool connected, string error = "") => new(
        new Dictionary<string, ClassicBluetoothDevice>(StringComparer.OrdinalIgnoreCase)
        { [Address] = new(Address, "Galaxy S9+", 5898764, connected) }, error);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Classic_radio_state_overrides_stale_container_state(bool connected)
    {
        var actual = BluetoothConnectionState.Read(Phone, () => Snapshot(connected),
            _ => throw new Exception("Container must not be used for Classic devices"));
        Assert.Equal(connected, actual);
    }

    [Fact]
    public void Missing_Classic_device_does_not_fall_back_to_connected_container() =>
        Assert.Null(BluetoothConnectionState.Read(Phone, () => new(new Dictionary<string, ClassicBluetoothDevice>()), _ => true));

    [Fact]
    public void Failed_partial_Classic_query_is_unknown() =>
        Assert.Null(BluetoothConnectionState.Read(Phone, () => Snapshot(true, "Access denied"), _ => true));

    [Fact]
    public void Disconnected_Samsung_stays_in_history_but_is_not_live()
    {
        var snapshot = WindowsPnpSnapshot.Capture(() => [Phone], () => [],
            id => BluetoothConnectionState.Read(id, () => Snapshot(false), _ => true));
        var device = new UsbDeviceRecord { DeviceInstanceId = Phone, IsCurrentlyConnected = true };
        Assert.False(snapshot.ToIndex().GetConnectionState(device));
    }

    [Fact]
    public void Native_class_identifies_phone_even_if_registry_cache_lacks_COD()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Phone, FriendlyName = "Galaxy S9+" };
        Snapshot(false).Enrich([device]);
        DeviceTransportClassifier.Classify(device);
        Assert.Equal(DeviceKindResolver.PortableDevice, device.DeviceKind);
        Assert.False(device.IsCurrentlyConnected);
    }

    [Fact]
    public void Unknown_Bluetooth_address_does_not_inherit_another_phone_class()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Phone.Replace(Address, "112233445566") };
        Snapshot(false).Enrich([device]);
        Assert.Null(device.BluetoothClassOfDevice);
    }

    [Fact]
    public void LE_does_not_use_Classic_enumeration()
    {
        Assert.False(BluetoothConnectionState.Read(@"BTHLE\Dev_112233445566\7&123&0&112233445566",
            () => throw new Exception("Classic enumeration cannot establish LE state"), _ => false));
    }
}
