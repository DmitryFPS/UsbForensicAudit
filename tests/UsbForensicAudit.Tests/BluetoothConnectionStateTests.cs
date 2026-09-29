using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class BluetoothConnectionStateTests
{
    public static TheoryData<string> RemoteIds => new()
    {
        @"BTHENUM\Dev_887598C2F5F2\7&2768a9f8&0&BluetoothDevice_887598C2F5F2",
        @"BTHENUM\{0000112f-0000-1000-8000-00805f9b34fb}_VID&00010075_PID&0100\7&2768a9f8&0&887598C2F5F2_C00000000",
        @"BTHLE\Dev_887598c2f5f2\7&2832959&0&887598c2f5f2",
        @"BTHLEDEVICE\{00001800-0000-1000-8000-00805f9b34fb}_887598c2f5f2\8&26e4c222&1&0014",
        @"BTHHFENUM\BthHFPAudio\8&2b845b03&0&97"
    };

    [Theory]
    [MemberData(nameof(RemoteIds))]
    public void Present_pairing_uses_radio_connection_instead_of_pnp_presence(string id)
    {
        Assert.False(BluetoothConnectionState.Resolve(id, true, _ => false));
        Assert.True(BluetoothConnectionState.Resolve(id, true, _ => true));
        Assert.Throws<InvalidOperationException>(() => BluetoothConnectionState.Resolve(id, true, _ => null));
    }

    [Theory]
    [MemberData(nameof(RemoteIds))]
    public void Absent_node_does_not_require_a_container_that_was_already_removed(string id) =>
        Assert.False(BluetoothConnectionState.Resolve(id, false, _ => throw new Exception("Already absent")));

    [Theory]
    [InlineData(@"USB\VID_8087&PID_0033\RADIO")]
    [InlineData(@"BTH\MS_BTHBRB\6&2372791f&0&1")]
    [InlineData(@"USBSTOR\Disk&Ven_Test&Prod_Flash\ABC12345&0")]
    [InlineData(@"BTHENUM\Dev_000000000000\UNKNOWN")]
    public void Radio_and_other_devices_keep_their_pnp_protection(string id)
    {
        Assert.True(BluetoothConnectionState.Resolve(id, true, _ => throw new Exception("Not a remote Bluetooth device")));
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(255, true)]
    [InlineData(1, null)]
    public void Native_boolean_requires_a_valid_devprop_value(byte value, bool? expected) =>
        Assert.Equal(expected, BluetoothConnectionState.DecodeBoolean(value));

    [Fact]
    public void Missing_native_container_does_not_mean_disconnected() =>
        Assert.Null(BluetoothConnectionState.ReadContainer(Guid.NewGuid()));

    [Fact]
    public async Task Reconnection_after_preview_stops_unpair_before_any_command()
    {
        const string id = @"BTHENUM\Dev_887598C2F5F2\7&2768a9f8&0&BluetoothDevice_887598C2F5F2";
        var connected = false;
        var platform = new WindowsDeviceRemovalPlatform("unused",
            value => BluetoothConnectionState.Resolve(value, true, _ => connected), _ => true,
            (_, _, _) => throw new Exception("Must not remove a reconnected device"), () => { },
            removeBluetooth: _ => throw new Exception("Must not unpair a reconnected device"));
        Assert.False(platform.IsPresent(id));
        connected = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => platform.RemoveAsync(id));
    }
}
