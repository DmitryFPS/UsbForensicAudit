using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class UsbFlagsTests
{
    [Theory]
    [InlineData("0E0F00020000", "0E0F", "0002")]
    [InlineData("abcd12340001", "ABCD", "1234")]
    [InlineData("IgnoreHWSerNum0E0F0003", "0E0F", "0003")]
    public void TryParseUsbFlagsKey_extracts_vid_and_pid(string keyName, string expectedVid, string expectedPid)
    {
        var parsed = UsbRegistryCollector.TryParseUsbFlagsKey(keyName, out var vid, out var pid);

        Assert.True(parsed);
        Assert.Equal(expectedVid, vid);
        Assert.Equal(expectedPid, pid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0E0F0002")]
    [InlineData("VID_0E0F&PID_0002")]
    [InlineData("IgnoreHWSerNum-invalid")]
    public void TryParseUsbFlagsKey_rejects_unrelated_names(string keyName)
    {
        Assert.False(UsbRegistryCollector.TryParseUsbFlagsKey(keyName, out _, out _));
    }

    [Fact]
    public void TimelineEnricher_keeps_usbflags_as_non_connected_forensic_trace()
    {
        var lastWrite = new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero);
        var result = new AuditResult();
        var device = new UsbDeviceRecord
        {
            VisualCategory = "UsbFlagsTrace",
            DeviceType = "USBFlags",
            LastSeenUtc = lastWrite
        };
        result.Devices.Add(device);

        new TimelineEnricher().Enrich(result);

        Assert.False(device.IsCurrentlyConnected);
        Assert.Equal(lastWrite, device.LastSeenUtc);
        Assert.Contains("usbflags", device.DateConfidence, StringComparison.OrdinalIgnoreCase);
    }
}
