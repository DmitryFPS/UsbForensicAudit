using System.Buffers.Binary;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class Stage3IdentityAndVolumeTests
{
    [Fact]
    public void Same_vid_pid_with_different_exact_serials_remain_distinct()
    {
        var devices = new List<UsbDeviceRecord>
        {
            Device(@"USB\VID_1234&PID_5678\SERIAL-A", "SERIAL-A"),
            Device(@"USB\VID_1234&PID_5678\SERIAL-B", "SERIAL-B")
        };

        DeviceIdentityGraph.Process(devices);

        Assert.NotEqual(devices[0].CanonicalDeviceId, devices[1].CanonicalDeviceId);
    }

    [Fact]
    public void Generated_instance_ids_do_not_merge_even_with_same_vid_pid()
    {
        var devices = new List<UsbDeviceRecord>
        {
            Device(@"USB\VID_1234&PID_5678\5&ABCDEF&0&1", "5&ABCDEF&0&1"),
            Device(@"USB\VID_1234&PID_5678\5&ABCDEF&0&2", "5&ABCDEF&0&2")
        };

        DeviceIdentityGraph.Process(devices);

        Assert.False(DeviceIdentityGraph.IsHardwareSerial(devices[0].Serial));
        Assert.NotEqual(devices[0].CanonicalDeviceId, devices[1].CanonicalDeviceId);
    }

    [Fact]
    public void Wpd_node_merges_with_its_backing_usbstor_record()
    {
        var storage = Device(
            @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            "2412242109410569603146");
        var portable = Device(
            @"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412242109410569603146&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
            "2412242109410569603146");
        portable.IdentityAliases.Add(
            @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0");
        var devices = new List<UsbDeviceRecord> { storage, portable };

        DeviceIdentityGraph.Process(devices);

        Assert.Equal(storage.CanonicalDeviceId, portable.CanonicalDeviceId);
    }

    [Fact]
    public void Two_flash_drives_stay_separate_after_wpd_merge()
    {
        var devices = new List<UsbDeviceRecord>
        {
            Device(@"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0", "2412242109410569603146"),
            Device(@"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412281911546114543745&0", "2412281911546114543745")
        };

        DeviceIdentityGraph.Process(devices);

        Assert.NotEqual(devices[0].CanonicalDeviceId, devices[1].CanonicalDeviceId);
    }

    [Fact]
    public void Placeholder_container_id_does_not_merge_unrelated_devices()
    {
        const string placeholder = "{00000000-0000-0000-FFFF-FFFFFFFFFFFF}";
        var devices = new List<UsbDeviceRecord>
        {
            Device(@"USB\ROOT_HUB30\4&2dda3b82&0&0", "4&2dda3b82&0&0", placeholder),
            Device(@"SCSI\Disk&Ven_NVMe&Prod_T-FORCE\5&74ee85&0&000000", "5&74ee85&0&000000", placeholder),
            Device(@"PCI\VEN_8086&DEV_7EC2\3&11583659&0&6A", "3&11583659&0&6A", placeholder)
        };

        DeviceIdentityGraph.Process(devices);

        Assert.Equal(3, devices.Select(x => x.CanonicalDeviceId).Distinct().Count());
    }

    [Fact]
    public void Canonical_id_is_stable_across_runs()
    {
        static List<UsbDeviceRecord> Build() =>
        [
            Device(@"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0", "2412242109410569603146")
        ];

        var first = Build();
        var second = Build();
        DeviceIdentityGraph.Process(first);
        DeviceIdentityGraph.Process(second);

        Assert.Equal(first[0].CanonicalDeviceId, second[0].CanonicalDeviceId);
    }

    [Fact]
    public void Container_id_links_usb_and_uasp_records()
    {
        var container = "{8B202FD7-8D72-4124-A711-C3849D29F245}";
        var devices = new List<UsbDeviceRecord>
        {
            Device(@"USB\VID_1234&PID_5678\SERIAL-A", "SERIAL-A", container),
            new()
            {
                Source = "Registry: SCSI",
                VisualCategory = "RelatedStorage",
                DeviceType = "SCSI Storage",
                DeviceInstanceId = @"SCSI\DISK&VEN_TEST&PROD_DISK\7&111&0&000000",
                Serial = "7&111&0&000000",
                ContainerId = container
            }
        };

        DeviceIdentityGraph.Process(devices);

        Assert.Equal(devices[0].CanonicalDeviceId, devices[1].CanonicalDeviceId);
        Assert.Contains(devices[0].IdentityProvenance, x => x.StartsWith("ContainerID", StringComparison.Ordinal));
    }

    [Fact]
    public void Composite_mi_interfaces_link_only_by_exact_hardware_serial()
    {
        var devices = new List<UsbDeviceRecord>
        {
            Device(@"USB\VID_1234&PID_5678&MI_00\PHONE123", "PHONE123"),
            Device(@"USB\VID_1234&PID_5678&MI_01\PHONE123", "PHONE123"),
            Device(@"USB\VID_1234&PID_5678&MI_01\PHONE999", "PHONE999")
        };

        DeviceIdentityGraph.Process(devices);

        Assert.Equal(devices[0].CanonicalDeviceId, devices[1].CanonicalDeviceId);
        Assert.NotEqual(devices[0].CanonicalDeviceId, devices[2].CanonicalDeviceId);
    }

    [Fact]
    public void Mounted_devices_parser_reads_utf16_path()
    {
        var data = Encoding.Unicode.GetBytes(@"\??\USBSTOR#Disk&Ven_Test&Prod_Disk#SERIAL-A#{GUID}" + "\0");

        var parsed = MountedDevicesParser.Parse(@"\DosDevices\E:", data);

        Assert.Equal("E:", parsed.DriveLetter);
        Assert.Contains("USBSTOR", parsed.DevicePath);
    }

    [Fact]
    public void Mounted_devices_parser_reads_escaped_removable_device_path()
    {
        // Реальное значение \DosDevices\E: с исследованной машины.
        var raw = "_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412242109410569603146&0"
                  + "#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
        var data = Encoding.Unicode.GetBytes(raw + "\0");

        var parsed = MountedDevicesParser.Parse(@"\DosDevices\E:", data);

        Assert.Equal("E:", parsed.DriveLetter);
        Assert.Equal("High", parsed.Confidence);
        Assert.Equal(
            @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            parsed.DevicePath);
        Assert.DoesNotContain(parsed.Provenance, x => x.Contains("Unrecognized", StringComparison.Ordinal));
    }

    [Fact]
    public void Escaped_removable_mapping_links_drive_letter_to_its_device()
    {
        var result = new AuditResult();
        var device = Device(
            @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            "2412242109410569603146");
        result.Devices.Add(device);
        result.Devices.Add(new UsbDeviceRecord
        {
            Source = "Registry: MountedDevices",
            VisualCategory = "SupportArtifact",
            DeviceType = "VolumeMapping",
            DeviceInstanceId = @"HKLM\SYSTEM\MountedDevices\DosDevices\E:",
            Volumes =
            [
                MountedDevicesParser.Parse(
                    @"\DosDevices\E:",
                    Encoding.Unicode.GetBytes(
                        "_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412242109410569603146&0"
                        + "#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\0"))
            ]
        });

        DeviceIdentityGraph.Process(result.Devices);
        VolumeCorrelationService.Process(result);

        Assert.Contains("E:", device.DriveLetters, StringComparison.Ordinal);
    }

    [Fact]
    public void Mounted_devices_parser_reads_mbr_signature_and_offset()
    {
        var data = new byte[12];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 0xA1B2C3D4);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(4, 8), 1_048_576);

        var parsed = MountedDevicesParser.Parse(@"\DosDevices\F:", data);

        Assert.Equal("A1B2C3D4", parsed.DiskSignature);
        Assert.Equal(1_048_576, parsed.PartitionOffset);
    }

    [Fact]
    public void Mounted_devices_parser_reads_gpt_dmio_identifier()
    {
        var expected = Guid.Parse("8B202FD7-8D72-4124-A711-C3849D29F245");
        var data = new byte[24];
        Encoding.ASCII.GetBytes("DMIO:ID:").CopyTo(data, 0);
        expected.TryWriteBytes(data.AsSpan(8));

        var parsed = MountedDevicesParser.Parse(@"\??\Volume{11111111-2222-3333-4444-555555555555}", data);

        Assert.Equal(expected.ToString("D").ToUpperInvariant(), parsed.DiskId);
        Assert.Equal("11111111-2222-3333-4444-555555555555", parsed.VolumeGuid);
    }

    [Fact]
    public void Exact_lnk_vsn_correlates_and_registry_mapping_populates_drive()
    {
        var result = new AuditResult();
        var device = Device(@"USBSTOR\Disk&Ven_Test&Prod_Disk\SERIAL-A&0", "SERIAL-A");
        device.Volumes.Add(new VolumeIdentity
        {
            DriveLetter = "E:",
            VolumeSerialNumber = "A1B2C3D4",
            Source = "Live: WMI associations",
            Confidence = "High"
        });
        result.Devices.Add(device);
        result.Devices.Add(new UsbDeviceRecord
        {
            Source = "Registry: MountedDevices",
            VisualCategory = "SupportArtifact",
            DeviceType = "VolumeMapping",
            DeviceInstanceId = @"HKLM\SYSTEM\MountedDevices\DosDevices\E:",
            Volumes =
            [
                new VolumeIdentity
                {
                    MappingName = @"\DosDevices\E:",
                    DriveLetter = "E:",
                    DevicePath = @"\??\USBSTOR#Disk&Ven_Test&Prod_Disk#SERIAL-A&0#{GUID}",
                    Source = "Registry: MountedDevices"
                }
            ]
        });
        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            Source = "User Recent/LNK Parsed",
            DeviceHint = @"E:\case\report.docx",
            RawText = "VolumeSerial=A1B2C3D4"
        });

        DeviceIdentityGraph.Process(result.Devices);
        VolumeCorrelationService.Process(result);

        Assert.Equal("E:", device.DriveLetters);
        Assert.Contains(device.Volumes, x => x.DevicePath.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Evidence, x => x.Source == "Volume Correlation" && x.EventId == "High");
    }

    [Fact]
    public void Drive_letter_without_vsn_does_not_correlate_lnk()
    {
        var result = new AuditResult();
        var device = Device(@"USBSTOR\Disk&Ven_Test&Prod_Disk\SERIAL-A&0", "SERIAL-A");
        device.Volumes.Add(new VolumeIdentity { DriveLetter = "E:", Source = "Live: WMI associations" });
        result.Devices.Add(device);
        result.Evidence.Add(new EvidenceRecord
        {
            Source = "JumpList AutomaticDestinations",
            DeviceHint = @"E:\only-a-letter.txt",
            RawText = @"E:\only-a-letter.txt"
        });

        DeviceIdentityGraph.Process(result.Devices);
        VolumeCorrelationService.Process(result);

        Assert.DoesNotContain(result.Evidence, x => x.Source == "Volume Correlation");
    }

    private static UsbDeviceRecord Device(string id, string serial, string container = "") => new()
    {
        Source = "Registry: USB",
        VisualCategory = "RealUsb",
        DeviceType = "USB",
        DeviceInstanceId = id,
        Vid = "1234",
        Pid = "5678",
        Serial = serial,
        ContainerId = container
    };
}
