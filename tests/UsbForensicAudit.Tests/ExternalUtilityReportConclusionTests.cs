using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class ExternalUtilityReportConclusionTests
{
    [Fact]
    public void ReportConclusionRow_virtual_device()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["VID"] = "0E0F", ["PID"] = "0003" },
            PrimaryText = "VMware"
        };
        var a = ExternalUtilityRowExplainer.Assess(row, null);
        Assert.Contains("не физический", a.ReportConclusionRow, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReportConclusionCase_confirmed_usbdeview()
    {
        var audit = new AuditResult();
        audit.Devices.Add(new UsbDeviceRecord
        {
            Vid = "0951",
            Pid = "1666",
            DeviceInstanceId = @"USB\VID_0951&PID_1666\1",
            Source = "Registry",
            DeviceType = "USB"
        });
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Список устройств",
            UtilityName = "USBDeview",
            Values = new Dictionary<string, string> { ["Vendor ID"] = "0951", ["Product ID"] = "1666" },
            PrimaryText = "Kingston"
        };
        var a = ExternalUtilityRowExplainer.Assess(row, audit);
        Assert.Contains("USB", a.ReportConclusionCase, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReportConclusionCase_date_artifact()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["Первое подключение"] = "01.01.1970 03:00" },
            PrimaryText = "X"
        };
        var a = ExternalUtilityRowExplainer.Assess(row, new AuditResult());
        Assert.Equal(ExternalUtilityVerdictLevel.DateArtifact, a.Level);
        Assert.Contains("1970", a.ReportConclusionRow, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Assess_matches_device_by_serial_in_audit()
    {
        var audit = new AuditResult();
        audit.Devices.Add(new UsbDeviceRecord
        {
            FriendlyName = "Kingston",
            Serial = "0011223344556677",
            Vid = "0951",
            Pid = "1666",
            DeviceInstanceId = @"USB\VID_0951&PID_1666\0011223344556677",
            Source = "Registry: USB",
            DeviceType = "USB"
        });
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Основной список (реестр)",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["Serial"] = "0011223344556677" },
            PrimaryText = "Kingston"
        };
        var a = ExternalUtilityRowExplainer.Assess(row, audit);
        Assert.Equal(ExternalUtilityVerdictLevel.Confirmed, a.Level);
    }

    [Fact]
    public void ReportConclusionRow_indirect_mentions_origin()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["VID"] = "ABCD", ["PID"] = "0001" },
            PrimaryText = "Unknown"
        };
        var a = ExternalUtilityRowExplainer.Assess(row, new AuditResult());
        Assert.Contains("косвенный след", a.ReportConclusionRow, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FullExplanation_includes_source_checks_without_audit()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Основной список (реестр)",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["VID"] = "0951", ["PID"] = "1666" },
            PrimaryText = "Kingston"
        };
        var text = ExternalUtilityRowExplainer.Explain(row, null);
        Assert.Contains("ГДЕ ИСКАЛИ", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Сканирование не выполнялось", text, StringComparison.OrdinalIgnoreCase);
    }
}
