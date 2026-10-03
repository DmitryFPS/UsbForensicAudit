using System.Text;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class PresenceAndConnectorTests
{
    private const string Phone = @"BTHENUM\DEV_112233445566\7&123456&0&BLUETOOTHDEVICE_112233445566";
    private const string Usb = @"USB\VID_1234&PID_5678\AUDIT-SERIAL-42";

    [Fact]
    public void USB_node_keeps_its_transport_when_phone_has_Bluetooth_alias()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Usb, IdentityAliases = [Phone] };
        DeviceTransportClassifier.Classify(device);
        Assert.Equal("USB", device.Connection);
    }

    [Fact]
    public void WPD_with_conflicting_transport_aliases_remains_unknown()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = @"SWD\WPDBUSENUM\PHONE", IdentityAliases = [Usb, Phone] };
        DeviceTransportClassifier.Classify(device);
        Assert.Equal("Unknown", device.Connection);
    }

    [Fact]
    public void Live_refresh_prefers_exact_node_over_an_earlier_shared_container()
    {
        const string container = "78f6cf4f-9b91-4f1b-8e52-e3a35f58fa76";
        var sibling = new UsbDeviceRecord { DeviceInstanceId = Phone, ContainerId = container };
        var exact = new UsbDeviceRecord { DeviceInstanceId = Usb, ContainerId = container };
        var live = new UsbDeviceRecord { DeviceInstanceId = Usb, ContainerId = container };
        Assert.Same(exact, LiveDeviceMerger.FindMatch([sibling, exact], live));
    }

    [Fact]
    public void Live_refresh_does_not_overwrite_another_function_of_the_same_device()
    {
        const string container = "78f6cf4f-9b91-4f1b-8e52-e3a35f58fa76";
        var sibling = new UsbDeviceRecord { DeviceInstanceId = Phone, ContainerId = container };
        var live = new UsbDeviceRecord { DeviceInstanceId = Usb, ContainerId = container };
        Assert.Null(LiveDeviceMerger.FindMatch([sibling], live));
    }

    [Fact]
    public void Both_failed_sources_report_unknown_not_disconnected()
    {
        var snapshot = WindowsPnpSnapshot.Capture(() => throw new UnauthorizedAccessException("native denied"),
            () => throw new UnauthorizedAccessException("WMI denied"), _ => true);
        Assert.False(snapshot.Complete);
        Assert.Contains("native denied", snapshot.Error);
        Assert.Contains("WMI denied", snapshot.Error);
        var device = new UsbDeviceRecord { DeviceInstanceId = Usb, LastSeenUtc = DateTimeOffset.UtcNow.AddDays(-1) };
        var result = new AuditResult();
        result.Devices.Add(device);
        new TimelineEnricher(new Probe(snapshot.ToIndex())).Enrich(result);
        Assert.Equal("Unknown", device.CurrentConnectionState);
        Assert.Equal("ConnectionUnknown", device.DisconnectDisplayKind);
        Assert.Null(device.LastDisconnectedUtc);
        Assert.Contains(DeviceCardModel.FieldsOf(device), f => f.Label == "Подключено сейчас" && f.Value == "Не удалось проверить");
        Assert.NotEmpty(result.SourceWarnings);
    }

    [Fact]
    public void Successful_WMI_fallback_retains_present_devices_and_warning()
    {
        var snapshot = WindowsPnpSnapshot.Capture(() => throw new InvalidOperationException("native"), () => [Usb], _ => false);
        Assert.True(snapshot.Complete);
        Assert.True(snapshot.ToIndex().IsConnected(new() { DeviceInstanceId = Usb }));
        Assert.Contains("WMI", snapshot.Error);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [InlineData(null)]
    public void Bluetooth_presence_does_not_replace_radio_connection(bool? connection)
    {
        var snapshot = WindowsPnpSnapshot.Capture(() => [Phone], () => throw new InvalidOperationException(), _ => connection);
        Assert.Equal(connection, snapshot.ToIndex().GetConnectionState(new() { DeviceInstanceId = Phone, IsCurrentlyConnected = true }));
    }

    [Fact]
    public void Connected_USB_function_does_not_prove_Bluetooth_radio_connection()
    {
        var snapshot = WindowsPnpSnapshot.Capture(() => [Phone, Usb], () => [], _ => false);
        var device = new UsbDeviceRecord { DeviceInstanceId = Phone, Connection = "Bluetooth", LinkedSourceIds = [Phone, Usb] };
        Assert.False(snapshot.ToIndex().IsConnected(device));
    }

    [Fact]
    public void Throwing_Bluetooth_query_remains_unknown()
    {
        var snapshot = WindowsPnpSnapshot.Capture(() => [Phone], () => [], _ => throw new InvalidOperationException());
        Assert.Null(snapshot.ToIndex().GetConnectionState(new() { DeviceInstanceId = Phone }));
        Assert.Contains("Bluetooth", snapshot.Error);
    }

    [Fact]
    public void Empty_successful_snapshot_clears_previous_positive_flag()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Usb, IsCurrentlyConnected = true };
        var result = new AuditResult();
        result.Devices.Add(device);
        new TimelineEnricher(new Probe(ConnectedDeviceIndex.Build([], []))).Enrich(result);
        Assert.False(device.IsCurrentlyConnected);
        Assert.Equal("Disconnected", device.CurrentConnectionState);
    }

    [Fact]
    public void Bluetooth_PnP_event_is_saved_without_inventing_a_radio_session()
    {
        var parsed = new ParsedEventLogRecord("Microsoft-Windows-Kernel-PnP", "Microsoft-Windows-Kernel-PnP/Configuration", 400, 1, "TEST", DateTimeOffset.UtcNow,
            new Dictionary<string, string> { ["DeviceInstanceId"] = Phone }, "");
        var evidence = EventLogRecordParser.ToEvidence(parsed)!;
        Assert.NotNull(evidence);
        Assert.False(evidence.CanEstablishConnectionDate);
    }

    [Fact]
    public void Bluetooth_SetupAPI_keeps_installation_without_radio_session()
    {
        using var reader = new System.IO.StringReader($">>>  [Device Install (Hardware initiated) - {Phone}]\n>>>  Section start 2026/07/11 10:15:20.125\n<<<  Section end");
        var evidence = Assert.Single(SetupApiLogParser.Parse(reader, "SetupAPI"));
        Assert.Equal(Phone, evidence.DeviceHint);
        Assert.False(evidence.CanEstablishConnectionDate);
    }

    [Fact]
    public void WPD_with_explicit_Bluetooth_parent_is_not_USB()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = @"SWD\WPDBUSENUM\PHONE", ParentDeviceInstanceId = Phone };
        DeviceTransportClassifier.Classify(device);
        Assert.Equal("Bluetooth", device.Connection);
        Assert.Equal("MTP/PTP/WPD", device.Transport);
        Assert.DoesNotContain("По USB", device.TransportDisplayText);
    }

    [Fact]
    public void Bluetooth_phone_kind_uses_declared_class_not_display_name()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Phone, BluetoothClassOfDevice = 0x5A020C };
        DeviceTransportClassifier.Classify(device);
        Assert.Equal(DeviceKindResolver.PortableDevice, device.DeviceKind);
        device.BluetoothClassOfDevice = null;
        device.FriendlyName = "My phone";
        DeviceTransportClassifier.Classify(device);
        Assert.Equal(DeviceKindResolver.Unknown, device.DeviceKind);
    }

    [Theory]
    [InlineData("Port_#0004.Hub_#0001", 4u)]
    [InlineData("Port_#0000.Hub_#0001", 0u)]
    [InlineData("Port_#1000.Hub_#0001", 0u)]
    [InlineData("USB-C port 1", 0u)]
    public void Connector_port_must_be_an_exact_valid_location(string location, uint expected) => Assert.Equal(expected, UsbConnectorProbe.ParsePort(location));

    [Fact]
    public void TypeC_requires_valid_full_response_for_the_requested_port()
    {
        var bytes = new byte[18];
        BitConverter.GetBytes(4u).CopyTo(bytes, 0);
        BitConverter.GetBytes(18u).CopyTo(bytes, 4);
        BitConverter.GetBytes(8u).CopyTo(bytes, 8);
        Assert.True(UsbConnectorProbe.DecodeTypeC(bytes, 4));
        Assert.False(UsbConnectorProbe.DecodeTypeC(bytes, 5));
        Assert.False(UsbConnectorProbe.DecodeTypeC(bytes[..12], 4));
        bytes[8] = 0;
        Assert.False(UsbConnectorProbe.DecodeTypeC(bytes, 4));
    }

    [Fact]
    public void Connector_driver_key_must_match_the_exact_device()
    {
        const string driver = @"{36fc9e60-c465-11cf-8056-444553540000}\0042";
        var name = Encoding.Unicode.GetBytes(driver + "\0");
        var bytes = new byte[8 + name.Length];
        BitConverter.GetBytes((uint)bytes.Length).CopyTo(bytes, 4);
        name.CopyTo(bytes, 8);
        Assert.True(UsbConnectorProbe.DriverKeyMatches(bytes, driver));
        Assert.False(UsbConnectorProbe.DriverKeyMatches(bytes, driver + "-OTHER"));
        Assert.False(UsbConnectorProbe.DriverKeyMatches(bytes[..9], driver));
    }

    [Fact]
    public void Historical_USB_record_does_not_claim_TypeC()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Usb };
        DeviceTransportClassifier.Classify(device);
        Assert.Equal("Unknown", device.ConnectorType);
        Assert.Contains("тип разъёма не установлен", device.TransportDisplayText);
    }

    [Fact]
    public void Shared_port_path_does_not_reclassify_an_internal_disk_as_USB()
    {
        var disk = new UsbDeviceRecord { DeviceInstanceId = @"SCSI\Disk&Ven_NVMe&Prod_Internal\5&74EE85&0&0", Service = "disk", LocationPaths = "PCIROOT(0)#PCI(0100)" };
        var usb = new UsbDeviceRecord { DeviceInstanceId = Usb, Service = "UASPStor", LocationPaths = "PCIROOT(0)#PCI(0100)#USBROOT(0)#USB(4)" };
        DeviceTransportClassifier.ClassifyAll([disk, usb]);
        Assert.Equal("BuiltIn", disk.Classification);
    }

    private sealed class Probe(ConnectedDeviceIndex index) : IConnectedDeviceProbe
    {
        public ConnectedDeviceIndex Capture() => index;
    }
}
