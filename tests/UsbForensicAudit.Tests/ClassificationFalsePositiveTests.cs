using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class ClassificationFalsePositiveTests
{
    [Fact]
    public void Scsi_device_type_label_does_not_trigger_uasp_transport()
    {
        var device = Device(@"SCSI\Disk&Ven_WDC&Prod_Blue\5&abc&0&000000");
        device.DeviceType = "SCSI Storage";
        device.Service = "disk";
        device.HardwareIds = @"SCSI\DiskWDC_WD10EZEX\0GenDisk";
        device.LocationInformation = "Bus Number 0, Target Id 0, LUN 0";

        DeviceTransportClassifier.Classify(device);

        Assert.NotEqual("UASP/SCSI", device.Transport);
        Assert.Equal("BuiltIn", device.Classification);
        Assert.False(DeviceTransportClassifier.IsReportable(device));
    }

    [Fact]
    public void Legacy_scsi_uasp_storage_label_does_not_trigger_uasp_transport()
    {
        var device = Device(@"SCSI\Disk&Ven_WDC&Prod_Blue\5&abc&0&000000");
        device.DeviceType = "SCSI/UASP Storage";
        device.Service = "disk";
        device.HardwareIds = @"SCSI\DiskWDC_WD10EZEX\0GenDisk";

        DeviceTransportClassifier.Classify(device);

        Assert.NotEqual("UASP/SCSI", device.Transport);
        Assert.Equal("BuiltIn", device.Classification);
    }

    [Fact]
    public void Internal_sata_gen_disk_is_builtin_and_not_reportable()
    {
        var device = Device(@"SCSI\Disk&Ven_WDC&Prod_WD_BLUE\4&111&0&000000");
        device.Service = "disk";
        device.HardwareIds = @"SCSI\DiskWDC_WD10EZEX\0GenDisk";
        device.FriendlyName = "WDC WD10EZEX";

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("Internal Disk", device.Transport);
        Assert.Equal("BuiltIn", device.Classification);
        Assert.False(DeviceTransportClassifier.IsReportable(device));
    }

    [Fact]
    public void Msft_virtual_disk_is_virtual_not_external_usb()
    {
        var device = Device(@"SCSI\Disk&Ven_Msft&Prod_Virtual_Disk\2&123&0&000000");
        device.Service = "disk";
        device.HardwareIds = @"SCSI\DiskMsft____Virtual_Disk__\0GenDisk";

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("Virtual", device.Classification);
        Assert.False(DeviceTransportClassifier.IsReportable(device));
    }

    [Fact]
    public void Historical_migration_scsi_record_does_not_become_reportable_usb()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SCSI\Disk&Ven_NVMe&Prod_Internal\4&111&0&000000",
            Source = "Registry: DeviceMigration historical residual",
            VisualCategory = "HistoricalResidual",
            DeviceType = "SCSI Storage",
            Service = "disk",
            HardwareIds = @"SCSI\DiskNVMe__________________________Internal\0GenDisk",
            Connection = "HistoricalResidual"
        };

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("BuiltIn", device.Classification);
        Assert.False(DeviceTransportClassifier.IsReportable(device));
    }

    [Fact]
    public void ClassifyAll_does_not_attach_usb_connection_to_internal_nvme_with_shared_topology()
    {
        var containerId = "{11111111-2222-3333-4444-555555555555}";
        var nvme = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SCSI\Disk&Ven_NVMe&Prod_T-FORCE_TM8FPL50\5&74ee85&0&000000",
            Service = "disk",
            HardwareIds = @"SCSI\DiskNVMe__________________________T-FORCE_TM8FPL500G\0GenDisk",
            ContainerId = containerId,
            Source = "Registry: SCSI",
            VisualCategory = "RelatedStorage"
        };
        var usb = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_8087&PID_0026\5&abc&0&0",
            ContainerId = containerId,
            Source = "Registry: USB",
            VisualCategory = "RealUsb"
        };

        DeviceTransportClassifier.ClassifyAll([nvme, usb]);

        Assert.Equal("BuiltIn", nvme.Classification);
        Assert.Equal("Internal NVMe", nvme.Transport);
        Assert.NotEqual("USB", nvme.Connection);
        Assert.Equal("RelatedStorage", nvme.VisualCategory);
        Assert.False(DeviceTransportClassifier.IsReportable(nvme));
    }

    [Fact]
    public void External_uasp_disk_remains_reportable_with_explicit_markers()
    {
        var device = Device(@"SCSI\Disk&Ven_JMicron&Prod_Generic\7&456&0&000000");
        device.Service = "uaspstor";
        device.HardwareIds = @"SCSI\DiskJMicron_Generic\0USB Attached SCSI UAS";
        device.LocationPaths = "PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(4)";

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("UASP/SCSI", device.Transport);
        Assert.Equal("External", device.Classification);
        Assert.True(DeviceTransportClassifier.IsReportable(device));
    }

    [Theory]
    [InlineData("PLUS", "disk", "SCSI\\DiskPLUS\\0GenDisk")]
    [InlineData("FOCUS", "disk", "SCSI\\DiskFOCUS\\0GenDisk")]
    public void Product_names_with_accidental_letter_sequences_stay_internal_when_gen_disk(
        string productToken,
        string service,
        string hardwareIds)
    {
        var device = Device($@"SCSI\Disk&Ven_Test&Prod_{productToken}\7&1&0&000000");
        device.Service = service;
        device.HardwareIds = hardwareIds;

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("BuiltIn", device.Classification);
        Assert.False(DeviceTransportClassifier.IsReportable(device));
    }

    private static UsbDeviceRecord Device(string id) => new()
    {
        Source = "Registry: SCSI",
        VisualCategory = "RelatedStorage",
        DeviceType = "SCSI Storage",
        DeviceInstanceId = id
    };
}
