using Xunit;

namespace UsbForensicAudit.Tests;

// Audit probes: expected safe behavior. Failures reproduce gaps in the unchanged project.
public sealed class UsbMobileAuditTests
{
    [Fact]
    public void Placeholder_serial_must_not_copy_another_devices_connection_history()
    {
        var first = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_1234&PID_5678\000000000000", Serial = "000000000000" };
        var other = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_ABCD&PID_EF01\000000000000", Serial = "000000000000" };
        var result = new AuditResult();
        result.Devices.AddRange([first, other]);
        result.Evidence.Add(new EvidenceRecord { TimestampUtc = DateTimeOffset.UtcNow.AddDays(-1), DeviceHint = first.DeviceInstanceId, Source = "Microsoft-Windows-Kernel-PnP", EventId = "410", EvidenceCategory = "Подключение/инициализация устройства", CanEstablishConnectionDate = true });
        new TimelineEnricher().Enrich(result);
        Assert.NotNull(first.FirstConnectedUtc);
        Assert.Null(other.FirstConnectedUtc);
    }

    [Fact]
    public void Installation_driver_name_containing_stop_must_not_mean_disconnect()
    {
        const string log = ">>>  [Device Install (Hardware initiated) - USB\\VID_1234&PID_5678\\AUDIT-SERIAL-42]\n>>>  Section start 2026/07/11 10:15:20.125\n     inf: Opened INF: C:\\Drivers\\stopwatch.inf\n<<<  Section end";
        using var reader = new System.IO.StringReader(log);
        var evidence = Assert.Single(SetupApiLogParser.Parse(reader, "SetupAPI"));
        Assert.Equal("Установка/инициализация устройства", evidence.EvidenceCategory);
    }

    [Fact]
    public void Wpd_without_transport_evidence_must_not_prove_a_USB_cable()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = @"SWD\WPDBUSENUM\NETWORK-PORTABLE-DEVICE", Service = "WUDFWpdMtp" };
        DeviceTransportClassifier.Classify(device);
        Assert.Equal("MTP/PTP/WPD", device.Transport);
        Assert.NotEqual("USB", device.Connection);
    }

    [Fact]
    public void Scsi_disk_sharing_a_USB_container_must_not_be_declared_internal()
    {
        const string container = "{416a943f-5aec-42fe-9af2-1d435d879679}";
        var disk = new UsbDeviceRecord { DeviceInstanceId = @"SCSI\Disk&Ven_ADATA&Prod_SE800\6&24666AF7&0&000000", Service = "disk", CompatibleIds = @"SCSI\GenDisk", ContainerId = container };
        var bridge = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_125F&PID_A88A\AUDIT-SERIAL-42", Service = "UASPStor", ContainerId = container };
        DeviceTransportClassifier.ClassifyAll([disk, bridge]);
        Assert.NotEqual("BuiltIn", disk.Classification);
        Assert.Equal("USB", disk.Connection);
    }

    [Fact]
    public void SetupApi_SCSI_section_must_restore_its_exact_USB_parent()
    {
        const string child = @"SCSI\Disk&Ven_ADATA&Prod_SE800\6&24666AF7&0&000000";
        const string parent = @"USB\VID_125F&PID_A88A\AUDIT-SERIAL-42";
        var disk = new UsbDeviceRecord { DeviceInstanceId = child, Service = "disk", CompatibleIds = @"SCSI\GenDisk" };
        var evidence = new EvidenceRecord { Provider = "SetupAPI", RawText = $">>>  [Device Install (Hardware initiated) - {child}]\n     dvi: {{Install Device - {child}}}\n     dvi: Parent Device: {parent}\n<<<  Section end" };
        SetupApiDeviceRelations.Apply([disk], [evidence]);
        Assert.Equal(parent, disk.ParentDeviceInstanceId);
    }

    [Fact]
    public void Builtin_Thunderbolt_NHI_controller_must_not_prove_external_device()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = @"PCI\VEN_8086&DEV_15D2\3&11583659&0&00", Service = "nhi", FriendlyName = "Thunderbolt Controller", Source = "Registry: PCI USB4/Thunderbolt tunnel", DeviceType = "USB4/Thunderbolt PCI" };
        DeviceTransportClassifier.Classify(device);
        Assert.NotEqual("External", device.Classification);
    }

    [Fact]
    public void Different_generic_serial_instances_must_remain_distinct_in_live_list()
    {
        var first = LiveDeviceIdentity.StableKey(@"USB\VID_1234&PID_5678\MSFT-A", "1234", "5678");
        var second = LiveDeviceIdentity.StableKey(@"USB\VID_1234&PID_5678\MSFT-B", "1234", "5678");
        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Bluetooth_PnP_event_must_not_be_discarded_as_irrelevant()
    {
        var parsed = new ParsedEventLogRecord("Microsoft-Windows-Kernel-PnP", "Microsoft-Windows-Kernel-PnP/Configuration", 400, 42, "AUDIT-PC", DateTimeOffset.UtcNow,
            new Dictionary<string, string> { ["DeviceInstanceId"] = @"BTHENUM\DEV_112233445566\7&123456&0&BLUETOOTHDEVICE_112233445566" }, "");
        Assert.NotNull(EventLogRecordParser.ToEvidence(parsed));
    }

    [Fact]
    public void Generic_webcam_name_must_not_prove_it_is_built_in()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_046D&PID_0825\AUDIT-CAMERA", FriendlyName = "USB Webcam", Service = "usbvideo" };
        DeviceTransportClassifier.Classify(device);
        Assert.NotEqual("BuiltIn", device.Classification);
    }

    [Fact]
    public void Fresh_empty_presence_snapshot_must_not_keep_an_old_live_flag()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_1234&PID_5678\AUDIT-OLD", IsCurrentlyConnected = true };
        Assert.False(ConnectedDeviceIndex.Build([], []).IsConnected(device));
    }

    [Fact]
    public void Control_explicit_USB_storage_parent_is_recognized()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = @"SCSI\Disk&Ven_ADATA&Prod_SE800\6&24666AF7&0&000000", Service = "disk", CompatibleIds = @"SCSI\GenDisk", ParentDeviceInstanceId = @"USB\VID_125F&PID_A88A\AUDIT-SERIAL-42" };
        DeviceTransportClassifier.Classify(device);
        Assert.Equal("USB", device.Connection);
        Assert.Equal("External", device.Classification);
    }

    [Fact]
    public void Control_distinct_real_serials_are_not_merged_in_live_list()
    {
        Assert.NotEqual(LiveDeviceIdentity.StableKey(@"USB\VID_1234&PID_5678\AUDIT-SERIAL-A", "1234", "5678"), LiveDeviceIdentity.StableKey(@"USB\VID_1234&PID_5678\AUDIT-SERIAL-B", "1234", "5678"));
    }

    [Fact]
    public void Control_paired_bluetooth_without_radio_connection_is_not_connected()
    {
        Assert.False(BluetoothConnectionState.Resolve(@"BTHENUM\DEV_112233445566\7&123456&0&BLUETOOTHDEVICE_112233445566", true, _ => false));
    }
}
