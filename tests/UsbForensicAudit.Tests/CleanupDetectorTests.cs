using System.Runtime.InteropServices;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class CleanupDetectorTests
{
    [Fact]
    public void Analyze_detects_usb_trace_cleaner_prefetch_execution()
    {
        var timestamp = DateTimeOffset.UtcNow.AddHours(-2);
        var result = CreateResult(
            new EvidenceRecord
            {
                TimestampUtc = timestamp,
                Source = "Prefetch",
                EventId = "CLEANER_EXECUTION",
                Summary = "Prefetch: USB Trace Cleaner",
                DeviceHint = @"C:\Users\adm\Desktop\USBTraceCleaner.exe",
                RawText = "Executable=USBTRACECLEANER_V1.6.0.EXE-5F6F6390.pf"
            });

        var findings = new CleanupDetector().Analyze(result);

        Assert.Contains(findings, x =>
            x.PossibleTool == "USB Trace Cleaner"
            && x.ActionKind == "ToolLaunch"
            && x.Area == "Cleaner Artifacts");
    }

    [Fact]
    public void Analyze_marks_readonly_prefetch_as_probable_cleanup()
    {
        var timestamp = DateTimeOffset.UtcNow.AddHours(-1);
        var result = CreateResult(
            new EvidenceRecord
            {
                TimestampUtc = timestamp,
                Source = "Prefetch",
                EventId = "CLEANER_PREFETCH_TAMPER",
                Summary = "Prefetch (read-only): USB Trace Cleaner",
                DeviceHint = @"C:\Tools\USBTraceCleaner.exe",
                RawText = "Executable=USBTRACECLEANER_V1.6.0.EXE-5F6F6390.pf; ReadOnly=True"
            });

        var findings = new CleanupDetector().Analyze(result);

        Assert.Contains(findings, x =>
            x.PossibleTool == "USB Trace Cleaner"
            && x.ActionKind == "ProbableCleanup"
            && x.Details.Contains("read-only", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Analyze_detects_bam_execution_when_prefetch_missing()
    {
        var timestamp = DateTimeOffset.UtcNow.AddHours(-3);
        var result = CreateResult(
            new EvidenceRecord
            {
                TimestampUtc = timestamp,
                Source = "BAM Parsed",
                EventId = "BAM_EXECUTION",
                Summary = "BAM executable record: \\Device\\HarddiskVolume3\\Tools\\USBTraceCleaner.exe",
                DeviceHint = @"\Device\HarddiskVolume3\Tools\USBTraceCleaner.exe",
                ResolvedUserName = @"DESKTOP\adm"
            });

        var findings = new CleanupDetector().Analyze(result);

        Assert.Contains(findings, x =>
            x.PossibleTool == "USB Trace Cleaner"
            && x.ActionKind == "ToolLaunch"
            && x.Details.Contains("Prefetch не найден", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Analyze_keeps_setupapi_and_correlation_findings_without_cleaner_artifacts()
    {
        var result = CreateResult();
        result.Devices.Add(new UsbDeviceRecord
        {
            Source = "Registry: USBSTOR",
            DeviceInstanceId = "USBSTOR\\Disk&Ven_Test&Prod_Test&Rev_1.0\\SERIAL",
            FriendlyName = "Test USB"
        });

        var findings = new CleanupDetector().Analyze(result);

        Assert.Contains(findings, x => x.Area == "SetupAPI" || x.Area == "Correlation");
    }

    [Fact]
    public void Live_collectors_surface_known_cleaner_tools_on_developer_machine()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        var warnings = new List<string>();
        var evidence = new List<EvidenceRecord>();
        evidence.AddRange(new ExecutionArtifactCollector().Collect(warnings));
        evidence.AddRange(new ProcessAttributionCollector().Collect(warnings));

        var tools = evidence
            .Select(CleanerEvidenceClassifier.Analyze)
            .Where(x => x?.SupportsExecution == true)
            .Select(x => x!.Tool)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.NotEmpty(tools);
        Assert.Contains(tools, x => x.Contains("USB", StringComparison.OrdinalIgnoreCase));

        var result = CreateResult(evidence.ToArray());
        var findings = new CleanupDetector().Analyze(result);
        Assert.NotEmpty(findings);
        Assert.Contains(findings, x => x.Area == "Cleaner Artifacts");
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
