using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class DeviceLiveMatcherTests
{
    [Fact]
    public void PnpIdsMatch_ignores_case_and_hash_prefix()
    {
        Assert.True(DeviceLiveMatcher.PnpIdsMatch(
            @"SCSI\Disk&Ven_NVMe&Prod_T-FORCE_TM8FPL50\5&74ee85&0&000000",
            @"SCSI\DISK&VEN_NVME&PROD_T-FORCE_TM8FPL50\5&74EE85&0&000000"));
    }

    [Fact]
    public void AreLikelySameDevice_matches_registry_and_live_scsi_disk()
    {
        var registry = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SCSI\Disk&Ven_JMicron&Prod_Generic\7&456&0&000000",
            FriendlyName = "External USB Disk"
        };
        var live = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SCSI\DISK&VEN_JMICRON&PROD_GENERIC\7&456&0&000000",
            FriendlyName = "External USB Disk"
        };

        Assert.True(DeviceLiveMatcher.AreLikelySameDevice(registry, live));
    }

    [Fact]
    public void Internal_tforce_nvme_is_not_reportable_usb_device()
    {
        var device = new UsbDeviceRecord
        {
            Source = "Registry: SCSI",
            VisualCategory = "RelatedStorage",
            DeviceInstanceId = @"SCSI\Disk&Ven_NVMe&Prod_T-FORCE_TM8FPL50\5&74ee85&0&000000",
            DeviceType = "SCSI Storage",
            Service = "disk",
            FriendlyName = "T-FORCE TM8FPL500G",
            HardwareIds = @"SCSI\DiskNVMe__________________________T-FORCE_TM8FPL500G\0GenDisk"
        };

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("BuiltIn", device.Classification);
        Assert.Equal("Internal NVMe", device.Transport);
        Assert.False(DeviceTransportClassifier.IsReportable(device));
        Assert.False(DeviceTransportClassifier.IsRelevantLiveCandidate(
            device.DeviceInstanceId,
            device.Service,
            device.HardwareIds,
            name: device.FriendlyName,
            mediaType: "Fixed hard disk media"));
        Assert.True(DeviceTransportClassifier.IsBuiltinStorageLiveCandidate(
            device.DeviceInstanceId,
            device.Service,
            device.HardwareIds,
            name: device.FriendlyName,
            mediaType: "Fixed hard disk media"));
    }

    [Fact]
    public void ApplyLiveConnectionState_sets_connected_now_and_scan_time()
    {
        var scanTime = new DateTimeOffset(2026, 7, 11, 17, 0, 0, TimeSpan.Zero);
        var registry = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SCSI\Disk&Ven_NVMe&Prod_T-FORCE_TM8FPL50\5&74ee85&0&000000",
            DateConfidence = "Windows помнит устройство, но когда его подключали — неизвестно."
        };
        var live = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SCSI\DISK&VEN_NVME&PROD_T-FORCE_TM8FPL50\5&74EE85&0&000000",
            FirstConnectedUtc = scanTime,
            LastSeenUtc = scanTime,
            ConnectionDisplayKind = "LiveAtScan",
            DisconnectDisplayKind = "ConnectedNow"
        };

        LiveDeviceMerger.ApplyLiveConnectionState(registry, live, scanTime);

        Assert.True(registry.IsCurrentlyConnected);
        Assert.Equal(scanTime, registry.FirstConnectedUtc);
        Assert.Equal("ConnectedNow", registry.DisconnectDisplayKind);
        Assert.Equal("LiveAtScan", registry.ConnectionDisplayKind);
    }
}
