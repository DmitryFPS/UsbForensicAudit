using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Следы развёртывания системы из подготовленного образа: разбор дат
/// CloneTag и остатки виртуальной машины в истории устройств.
/// </summary>
public sealed class ReferenceImageDetectorTests
{
    [Theory]
    [InlineData("Sun Jul 27 06:33:56 2026")]
    [InlineData("Jul 27 06:33:56 2026")]
    [InlineData("2026-07-27T06:33:56")]
    [InlineData("2026-07-27 06:33:56")]
    public void Clone_tag_date_is_parsed_in_all_known_formats(string value)
    {
        var parsed = ReferenceImageDetector.ParseCloneTagDate(value);

        Assert.NotNull(parsed);
        Assert.Equal(new DateTimeOffset(2026, 7, 27, 6, 33, 56, TimeSpan.Zero), parsed.Value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("не дата вовсе")]
    public void Clone_tag_garbage_returns_null(string? value)
    {
        Assert.Null(ReferenceImageDetector.ParseCloneTagDate(value));
    }

    [Fact]
    public void Hypervisor_residue_on_physical_machine_is_reported()
    {
        var warnings = new List<string>();
        var devices = new[]
        {
            new UsbDeviceRecord
            {
                DeviceInstanceId = @"USB\VID_0E0F&PID_0003\VMWARE-MOUSE",
                FriendlyName = "VMware Pointing Device"
            },
            new UsbDeviceRecord
            {
                DeviceInstanceId = @"USB\VID_0951&PID_1666\REAL-STICK",
                FriendlyName = "Kingston DataTraveler"
            }
        };

        var trace = ReferenceImageDetector.Detect(devices, warnings);

        Assert.Contains(trace.Signals, x => x.Title == "Следы виртуальной машины в истории");
    }

    [Fact]
    public void Hypervisor_residue_is_silent_when_machine_is_virtual_now()
    {
        var warnings = new List<string>();
        var devices = new[]
        {
            new UsbDeviceRecord
            {
                DeviceInstanceId = @"USB\VID_0E0F&PID_0003\VMWARE-MOUSE",
                FriendlyName = "VMware Pointing Device"
            },
            new UsbDeviceRecord
            {
                DeviceInstanceId = @"USB\VID_0E0F&PID_0002\VBOX-DISK",
                FriendlyName = "VirtualBox Disk",
                IsCurrentlyConnected = true,
                Classification = "Virtual"
            }
        };

        var trace = ReferenceImageDetector.Detect(devices, warnings);

        Assert.DoesNotContain(trace.Signals, x => x.Title == "Следы виртуальной машины в истории");
    }
}
