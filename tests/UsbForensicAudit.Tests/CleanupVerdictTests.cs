using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Запуск утилиты работы с USB и наличие средства удаления следов не
/// доказывают очистку, поэтому подозрительными их называть нельзя. Но сводка,
/// которая в тот же день пишет «ничего не обнаружено», вводит читателя в
/// заблуждение сильнее, чем завышенная оценка.
/// </summary>
public class CleanupVerdictTests
{
    [Fact]
    public void Tool_launch_is_not_suspicious_but_needs_attention()
    {
        var finding = new CleanupFinding
        {
            PossibleTool = "USBDeview",
            ActionKind = "ToolLaunch",
            Assessment = "Informational",
            Severity = "Low"
        };

        Assert.False(finding.IsSuspicious);
        Assert.True(finding.NeedsAttention);
    }

    [Fact]
    public void Presence_of_a_trace_removal_tool_needs_attention()
    {
        var finding = new CleanupFinding
        {
            PossibleTool = "USB Oblivion",
            ActionKind = "ToolPresence",
            Assessment = "Informational",
            Severity = "Low"
        };

        Assert.True(finding.NeedsAttention);
    }

    [Fact]
    public void Windows_setup_log_clear_does_not_need_attention()
    {
        var finding = new CleanupFinding
        {
            PossibleTool = "Windows Setup / PnP",
            ActionKind = "OsInstall",
            Assessment = "OsInstall",
            Severity = "Info"
        };

        Assert.False(finding.NeedsAttention);
    }

    [Fact]
    public void Verdict_never_claims_nothing_found_while_a_usb_utility_was_launched()
    {
        var result = BuildResult(new CleanupFinding
        {
            TimestampUtc = new DateTimeOffset(2026, 7, 31, 11, 17, 6, TimeSpan.Zero),
            PossibleTool = "USBDeview",
            ActionKind = "ToolLaunch",
            Assessment = "Informational",
            Severity = "Low",
            Area = "Cleaner Artifacts",
            InitiatorKind = "User",
            InitiatorAccount = @"ARM1\adm"
        });

        var verdict = ForensicReportContext.Create(result).CleanupVerdict();

        Assert.Contains("требующие внимания", verdict);
        Assert.Contains("USBDeview", verdict);
        Assert.DoesNotContain("не обнаружено. Отсутствие артефактов", verdict);
    }

    [Fact]
    public void Verdict_says_nothing_found_only_when_nothing_was_found()
    {
        var verdict = ForensicReportContext.Create(BuildResult()).CleanupVerdict();

        Assert.Contains("не обнаружено", verdict);
        Assert.DoesNotContain("требующие внимания", verdict);
    }

    private static AuditResult BuildResult(params CleanupFinding[] findings)
    {
        var result = new AuditResult { ComputerName = "ARM1" };
        result.CleanupFindings.AddRange(findings);
        return result;
    }
}
