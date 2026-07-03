using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class CorrelationServiceTests
{
    [Fact]
    public void BuildDeviceCorrelations_links_evidence_to_usb_device()
    {
        var result = new AuditResult();
        result.Devices.Add(new UsbDeviceRecord
        {
            FriendlyName = "Kingston",
            Vid = "0951",
            Pid = "1666",
            Serial = "001122334455",
            DeviceInstanceId = @"USB\VID_0951&PID_1666\001122334455",
            Source = "Registry: USB",
            DeviceType = "USB"
        });
        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = DateTimeOffset.Parse("2024-05-01T10:00:00Z"),
            Source = "Prefetch",
            Summary = "Prefetch USB path",
            RawText = "VID_0951&PID_1666",
            DeviceHint = "001122334455"
        });

        var correlations = new CorrelationService().BuildDeviceCorrelations(result);

        Assert.Single(correlations);
        Assert.Equal("Correlation", correlations[0].Source);
        Assert.Contains("Kingston", correlations[0].Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildDeviceCorrelations_skips_mounted_devices_artifacts()
    {
        var result = new AuditResult();
        result.Devices.Add(new UsbDeviceRecord
        {
            DeviceInstanceId = "VolumeMapping",
            Source = "MountedDevices",
            DeviceType = "VolumeMapping"
        });

        Assert.Empty(new CorrelationService().BuildDeviceCorrelations(result));
    }
}
