using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class Uuid1TimestampTests
{
    [Theory]
    // Реальные идентификаторы дисков двух флешек с исследованной машины.
    [InlineData("24d5bfde-8985-11f1-9850-91f58aedf3f0", "2026-07-27T06:33:56.6839774+00:00")]
    [InlineData("f7821a9f-8b1d-11f1-985e-9010576eda10", "2026-07-29T07:20:24.8007327+00:00")]
    public void Disk_identifier_yields_the_moment_the_media_was_partitioned(string diskId, string expected)
    {
        Assert.True(Uuid1Timestamp.TryDecode(diskId, out var createdUtc));
        Assert.Equal(DateTimeOffset.Parse(expected), createdUtc);
    }

    [Fact]
    public void Braces_and_spacing_are_tolerated()
    {
        Assert.True(Uuid1Timestamp.TryDecode(" {24d5bfde-8985-11f1-9850-91f58aedf3f0} ", out var createdUtc));
        Assert.Equal(2026, createdUtc.Year);
    }

    [Theory]
    [InlineData("8b202fd7-8d72-4124-a711-c3849d29f245")] // версия 4, времени не содержит
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("не guid")]
    [InlineData("")]
    [InlineData(null)]
    public void Values_without_an_embedded_timestamp_are_rejected(string? value)
    {
        Assert.False(Uuid1Timestamp.TryDecode(value, out _));
    }

    [Fact]
    public void Timestamp_before_1990_is_treated_as_implausible()
    {
        // Версия 1, но счётчик указывает на 1584 год.
        Assert.False(Uuid1Timestamp.TryDecode("00000001-0000-1000-8000-000000000000", out _));
    }

    [Fact]
    public void Connection_earlier_than_partitioning_is_reported_as_a_conflict()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412281911546114543745&0",
            Serial = "2412281911546114543745",
            VisualCategory = "RealUsb",
            FirstConnectedUtc = new DateTimeOffset(2026, 7, 29, 1, 43, 0, TimeSpan.Zero),
            Volumes =
            [
                new VolumeIdentity
                {
                    DiskId = "F7821A9F-8B1D-11F1-985E-9010576EDA10",
                    Source = "Registry: MountedDevices"
                }
            ]
        };
        var result = new AuditResult { Devices = { device } };

        DeviceIdentityGraph.Process(result.Devices);
        VolumeCorrelationService.Process(result);

        var anchor = Assert.Single(result.Evidence,
            x => x.Source.Contains("UUID", StringComparison.Ordinal));
        Assert.Contains("противоречив", anchor.Summary, StringComparison.Ordinal);
        Assert.Contains("противоречив", device.DateConfidence, StringComparison.Ordinal);
    }

    [Fact]
    public void Consistent_dates_produce_an_anchor_without_a_conflict()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            Serial = "2412242109410569603146",
            VisualCategory = "RealUsb",
            FirstConnectedUtc = new DateTimeOffset(2026, 7, 27, 12, 0, 0, TimeSpan.Zero),
            Volumes =
            [
                new VolumeIdentity
                {
                    DiskId = "24D5BFDE-8985-11F1-9850-91F58AEDF3F0",
                    Source = "Registry: MountedDevices"
                }
            ]
        };
        var result = new AuditResult { Devices = { device } };

        DeviceIdentityGraph.Process(result.Devices);
        VolumeCorrelationService.Process(result);

        var anchor = Assert.Single(result.Evidence,
            x => x.Source.Contains("UUID", StringComparison.Ordinal));
        Assert.DoesNotContain("противоречив", anchor.Summary, StringComparison.Ordinal);
    }
}
