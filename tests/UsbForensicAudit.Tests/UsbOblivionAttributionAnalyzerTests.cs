using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class UsbOblivionAttributionAnalyzerTests
{
    [Fact]
    public void Analyze_ignores_evidence_of_other_cleaners()
    {
        var result = CreateResult(new EvidenceRecord
        {
            TimestampUtc = DateTimeOffset.UtcNow.AddHours(-1),
            Source = "Prefetch",
            EventId = "CLEANER_EXECUTION",
            Summary = "Prefetch: CCleaner",
            DeviceHint = @"C:\Program Files\CCleaner\CCleaner.exe"
        });
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        Assert.Empty(findings);
    }

    [Fact]
    public void Analyze_ignores_oblivion_artifacts_that_do_not_prove_execution()
    {
        var result = CreateResult(OblivionLaunch(DateTimeOffset.UtcNow.AddHours(-1), eventId: "INVENTORY_PRESENCE"));
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        Assert.Empty(findings);
    }

    [Fact]
    public void Analyze_reports_plain_launch_as_medium_tool_launch()
    {
        var launchAtUtc = DateTimeOffset.UtcNow.AddHours(-1);
        var result = CreateResult(OblivionLaunch(launchAtUtc));
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        var finding = Assert.Single(findings);
        Assert.Equal(launchAtUtc, finding.TimestampUtc);
        Assert.Equal("Medium", finding.Severity);
        Assert.Equal("ToolLaunch", finding.ActionKind);
        Assert.Equal("Cleaner Artifacts", finding.Area);
        Assert.Equal("Confirmed", finding.Confidence);
        Assert.Equal("USB Oblivion", finding.PossibleTool);
        Assert.Contains("фактическое удаление не установлено", finding.Details, StringComparison.Ordinal);
    }

    [Fact]
    public void Analyze_reports_corroborating_execution_with_probable_confidence()
    {
        var result = CreateResult(OblivionLaunch(DateTimeOffset.UtcNow.AddHours(-1), eventId: "BAM_EXECUTION"));
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        var finding = Assert.Single(findings);
        Assert.Equal("ToolLaunch", finding.ActionKind);
        Assert.Equal("Probable", finding.Confidence);
    }

    [Fact]
    public void Analyze_escalates_launch_started_with_enable_switch()
    {
        var result = CreateResult(OblivionLaunch(DateTimeOffset.UtcNow.AddHours(-1), rawText: "CommandLine=USBOblivion.exe -enable -auto"));
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        var finding = Assert.Single(findings);
        Assert.Equal("High", finding.Severity);
        Assert.Equal("ProbableCleanup", finding.ActionKind);
        Assert.Equal("USB Oblivion", finding.Area);
        Assert.Equal("Probable", finding.Confidence);
        Assert.Contains("-enable", finding.Details, StringComparison.Ordinal);
    }

    [Fact]
    public void Analyze_escalates_launch_correlated_with_cleared_windows_log()
    {
        var launchAtUtc = DateTimeOffset.UtcNow.AddHours(-1);
        var result = CreateResult(
            OblivionLaunch(launchAtUtc),
            new EvidenceRecord
            {
                TimestampUtc = launchAtUtc.AddMinutes(-30),
                Source = "Security",
                EventId = "1102",
                Summary = "Журнал безопасности очищен"
            });
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        var finding = Assert.Single(findings);
        Assert.Equal("ProbableCleanup", finding.ActionKind);
        Assert.Contains("очистка журналов Windows (104/1102)", finding.Details, StringComparison.Ordinal);
    }

    [Fact]
    public void Analyze_escalates_launch_correlated_with_suspicious_setupapi_finding()
    {
        var launchAtUtc = DateTimeOffset.UtcNow.AddHours(-1);
        var result = CreateResult(OblivionLaunch(launchAtUtc));
        result.CleanupFindings.Add(new CleanupFinding
        {
            TimestampUtc = launchAtUtc.AddHours(-3),
            Area = "SetupAPI",
            Assessment = "Suspicious",
            Finding = "Разрыв в журнале установки устройств"
        });
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        var finding = Assert.Single(findings);
        Assert.Equal("ProbableCleanup", finding.ActionKind);
        Assert.Contains("В пределах 24 часов", finding.Details, StringComparison.Ordinal);
    }

    [Fact]
    public void Analyze_reports_registry_gap_counts()
    {
        var result = CreateResult(OblivionLaunch(DateTimeOffset.UtcNow.AddHours(-1), rawText: "CommandLine=USBOblivion.exe -enable"));
        result.Devices.Add(new UsbDeviceRecord { Source = "Registry: USBSTOR", DeviceInstanceId = "USBSTOR\\Disk&Ven_A\\S1" });
        result.Devices.Add(new UsbDeviceRecord { Source = "Registry: USBSTOR", DeviceInstanceId = "USBSTOR\\Disk&Ven_B\\S2" });
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        var finding = Assert.Single(findings);
        Assert.Contains("В реестре USBSTOR: 2, в setupapi.dev.log USB-записей: 0.", finding.Details, StringComparison.Ordinal);
    }

    [Fact]
    public void Analyze_does_not_report_registry_gap_when_setupapi_has_usb_records()
    {
        var launchAtUtc = DateTimeOffset.UtcNow.AddHours(-1);
        var result = CreateResult(
            OblivionLaunch(launchAtUtc, rawText: "CommandLine=USBOblivion.exe -enable"),
            new EvidenceRecord
            {
                TimestampUtc = launchAtUtc.AddDays(-5),
                Source = "setupapi.dev.log",
                EventId = "DEVICE_INSTALL",
                Summary = "Установлено USB устройство"
            });
        result.Devices.Add(new UsbDeviceRecord { Source = "Registry: USBSTOR", DeviceInstanceId = "USBSTOR\\Disk&Ven_A\\S1" });
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        var finding = Assert.Single(findings);
        Assert.DoesNotContain("В реестре USBSTOR:", finding.Details, StringComparison.Ordinal);
    }

    [Fact]
    public void Analyze_reports_mounted_devices_without_usb_records()
    {
        var result = CreateResult(OblivionLaunch(DateTimeOffset.UtcNow.AddHours(-1), rawText: "CommandLine=USBOblivion.exe -enable"));
        result.Devices.Add(new UsbDeviceRecord { Source = "Registry: MountedDevices", DeviceInstanceId = "\\??\\Volume{guid}" });
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        var finding = Assert.Single(findings);
        Assert.Contains("Найдены MountedDevices при отсутствии соответствующих USB-записей.", finding.Details, StringComparison.Ordinal);
    }

    [Fact]
    public void Analyze_reports_missing_and_recreated_setupapi_log()
    {
        var launchAtUtc = DateTimeOffset.UtcNow.AddHours(-1);
        var result = CreateResult(OblivionLaunch(launchAtUtc, rawText: "CommandLine=USBOblivion.exe -enable"));
        var findings = new List<CleanupFinding>
        {
            new()
            {
                TimestampUtc = launchAtUtc,
                Area = "Cleaner Artifacts",
                Assessment = "Suspicious",
                Finding = "setupapi.dev.log отсутствует"
            },
            new()
            {
                TimestampUtc = launchAtUtc,
                Area = "Cleaner Artifacts",
                Assessment = "Suspicious",
                Finding = "setupapi.dev.log подозрительно мал"
            }
        };

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        var finding = Assert.Single(findings, x => x.PossibleTool == "USB Oblivion");
        Assert.Contains("setupapi.dev.log отсутствует или пересоздан.", finding.Details, StringComparison.Ordinal);
        Assert.Contains("setupapi.dev.log подозрительно мал или недавно пересоздан.", finding.Details, StringComparison.Ordinal);
    }

    [Fact]
    public void Analyze_notes_that_discrepancies_are_not_linked_to_a_plain_launch()
    {
        var result = CreateResult(OblivionLaunch(DateTimeOffset.UtcNow.AddHours(-1)));
        result.Devices.Add(new UsbDeviceRecord { Source = "Registry: USBSTOR", DeviceInstanceId = "USBSTOR\\Disk&Ven_A\\S1" });
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        var finding = Assert.Single(findings);
        Assert.Equal("ToolLaunch", finding.ActionKind);
        Assert.Contains("не привязаны ко времени запуска", finding.Details, StringComparison.Ordinal);
    }

    [Fact]
    public void Analyze_upgrades_nearby_finding_and_appends_its_note_once()
    {
        var launchAtUtc = DateTimeOffset.UtcNow.AddHours(-1);
        var result = CreateResult(
            OblivionLaunch(launchAtUtc),
            OblivionLaunch(launchAtUtc.AddMinutes(-2), rawText: "CommandLine=USBOblivion.exe -enable"),
            OblivionLaunch(launchAtUtc.AddMinutes(-4), rawText: "CommandLine=USBOblivion.exe -enable"));
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        var finding = Assert.Single(findings);
        Assert.Equal("High", finding.Severity);
        Assert.Equal("ProbableCleanup", finding.ActionKind);
        Assert.Equal("USB Oblivion", finding.Area);
        Assert.Equal("Probable", finding.Confidence);
        Assert.Equal("Suspicious", finding.Assessment);
        var noteCount = finding.Details.Split("Специальная проверка USB Oblivion", StringSplitOptions.None).Length - 1;
        Assert.Equal(1, noteCount);
    }

    [Fact]
    public void Analyze_processes_only_the_ten_most_recent_launches()
    {
        var newestAtUtc = DateTimeOffset.UtcNow.AddDays(-1);
        var launches = Enumerable.Range(0, 12)
            .Select(offset => OblivionLaunch(newestAtUtc.AddHours(-offset)))
            .ToArray();
        var result = CreateResult(launches);
        var findings = new List<CleanupFinding>();

        UsbOblivionAttributionAnalyzer.Analyze(result, findings);

        Assert.Equal(10, findings.Count);
        Assert.Contains(findings, x => x.TimestampUtc == newestAtUtc);
        Assert.DoesNotContain(findings, x => x.TimestampUtc == newestAtUtc.AddHours(-10));
        Assert.DoesNotContain(findings, x => x.TimestampUtc == newestAtUtc.AddHours(-11));
    }

    private static EvidenceRecord OblivionLaunch(
        DateTimeOffset timestampUtc,
        string rawText = "",
        string eventId = "CLEANER_EXECUTION")
    {
        return new EvidenceRecord
        {
            TimestampUtc = timestampUtc,
            Source = "Prefetch",
            EventId = eventId,
            Summary = "Prefetch: USBOblivion",
            DeviceHint = @"C:\Tools\USBOblivion.exe",
            RawText = rawText
        };
    }

    private static AuditResult CreateResult(params EvidenceRecord[] evidence)
    {
        return new AuditResult
        {
            StartedAtUtc = DateTimeOffset.UtcNow,
            OsInstalledAtUtc = DateTimeOffset.UtcNow.AddYears(-2),
            Evidence = evidence.ToList()
        };
    }
}
