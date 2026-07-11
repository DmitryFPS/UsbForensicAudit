using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class ReportScopeTests
{
    [Fact]
    public void Report_scope_keeps_usb_and_excludes_unrelated_internal_hardware()
    {
        var result = new AuditResult();
        var externalUsb = Device("RealUsb", "Registry: USB", @"USB\VID_0951&PID_1666\SERIAL01", "0951", "1666", "SERIAL01");
        var internalUsb = Device("RealUsb", "Registry: USB", @"USB\VID_0BDA&PID_0129\INTERNAL01", "0BDA", "0129", "INTERNAL01");
        var linkedStorage = Device("RelatedStorage", "Registry: SCSI", @"SCSI\Disk&Ven_Kingston\SERIAL01", "", "", "SERIAL01");
        var internalNvme = Device("RelatedStorage", "Registry: SCSI", @"SCSI\Disk&Ven_NVMe\NVME0001", "", "", "NVME0001");
        var usbFlags = Device("UsbFlagsTrace", "Registry: usbflags", @"HKLM\SYSTEM\ControlSet001\Control\usbflags\095116660100", "0951", "1666", "");
        var mounted = new UsbDeviceRecord
        {
            VisualCategory = "SupportArtifact",
            DeviceType = "VolumeMapping",
            Source = "Registry: MountedDevices",
            DeviceInstanceId = @"HKLM\SYSTEM\MountedDevices"
        };
        result.Devices.AddRange([externalUsb, internalUsb, linkedStorage, internalNvme, usbFlags, mounted]);

        result.Evidence.Add(new EvidenceRecord
        {
            Source = "EventLog: System",
            DeviceHint = @"USB\VID_0951&PID_1666\SERIAL01",
            Summary = "USB device connected"
        });
        result.Evidence.Add(new EvidenceRecord
        {
            Source = "WMI",
            DeviceHint = "Win32_PhysicalMemory",
            Summary = "RAM module changed"
        });
        result.Evidence.Add(new EvidenceRecord
        {
            Source = "EventLog: Security",
            EventId = "1102",
            Summary = "Журнал очищен"
        });

        result.CleanupFindings.Add(new CleanupFinding
        {
            Assessment = "Suspicious",
            PossibleTool = "USB Oblivion",
            Finding = "Удаление следов USB"
        });
        result.CleanupFindings.Add(new CleanupFinding
        {
            Assessment = "Suspicious",
            PossibleTool = "Generic Cleaner",
            Finding = "Очистка временных файлов"
        });

        var context = ForensicReportContext.Create(result);

        Assert.Contains(externalUsb, context.ReportableDevices);
        Assert.Contains(internalUsb, context.ReportableDevices);
        Assert.Contains(linkedStorage, context.ReportableDevices);
        Assert.Contains(usbFlags, context.ReportableDevices);
        Assert.DoesNotContain(internalNvme, context.ReportableDevices);
        Assert.DoesNotContain(mounted, context.ReportableDevices);

        Assert.Equal(2, context.Timeline.Count);
        Assert.DoesNotContain(context.Timeline, x => x.DeviceHint == "Win32_PhysicalMemory");
        Assert.Single(context.CleanupFindings);
        Assert.Equal("USB Oblivion", context.CleanupFindings[0].PossibleTool);
    }

    private static UsbDeviceRecord Device(
        string category,
        string source,
        string id,
        string vid,
        string pid,
        string serial)
    {
        return new UsbDeviceRecord
        {
            VisualCategory = category,
            Source = source,
            DeviceInstanceId = id,
            Vid = vid,
            Pid = pid,
            Serial = serial
        };
    }
}
