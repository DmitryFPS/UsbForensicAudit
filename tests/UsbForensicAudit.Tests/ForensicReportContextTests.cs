using System;
using System.Linq;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Единый контекст отчётов: фильтрация и сортировка находок, вердикты,
/// сквозные сводки (эксфильтрация, политика, MITRE, хеши, карточка дела).
/// Политика, карточка дела и хеши передаются явно — тесты на диск не ходят.
/// </summary>
public sealed class ForensicReportContextTests
{
    private static AuditResult SampleResult()
    {
        var result = new AuditResult();
        result.StartedAtUtc = new DateTimeOffset(2026, 5, 1, 10, 0, 0, TimeSpan.Zero);
        result.FinishedAtUtc = result.StartedAtUtc.AddMinutes(2).AddSeconds(5);

        result.Devices.Add(new UsbDeviceRecord
        {
            DeviceKind = DeviceKindResolver.Storage,
            VisualCategory = "RealUsb",
            FriendlyName = "Kingston DataTraveler",
            Vid = "0951",
            Pid = "1666",
            Serial = "CORP-1",
            DeviceInstanceId = @"USBSTOR\Disk&Ven_Kingston\CORP-1"
        });

        result.CleanupFindings.Add(new CleanupFinding
        {
            TimestampUtc = new DateTimeOffset(2026, 5, 1, 9, 0, 0, TimeSpan.Zero),
            Severity = "High",
            Assessment = "Suspicious",
            Area = "Registry",
            ActionKind = "Deletion",
            Finding = "Очистка USBSTOR",
            Details = "Удалены ключи устройств"
        });
        result.CleanupFindings.Add(new CleanupFinding
        {
            TimestampUtc = new DateTimeOffset(2026, 5, 1, 8, 0, 0, TimeSpan.Zero),
            Severity = "Low",
            Assessment = "Normal",
            ActionKind = "ToolPresence",
            PossibleTool = "USB Oblivion",
            Area = "FileSystem",
            Finding = "Найдена утилита очистки"
        });

        return result;
    }

    private static ForensicReportContext CreateContext(AuditResult result, DevicePolicy? policy = null) =>
        ForensicReportContext.Create(
            result,
            externalUtilitySnapshot: null,
            policy: policy ?? DevicePolicy.None,
            caseMetadata: new CaseMetadata { CaseNumber = "Д-42", Examiner = "Орлов" },
            usbExecutableHashes: []);

    [Fact]
    public void Suspicious_and_attention_findings_are_split()
    {
        var ctx = CreateContext(SampleResult());

        Assert.Equal(1, ctx.SuspiciousCount);
        Assert.Equal(1, ctx.HighRiskCount);
        Assert.Equal(1, ctx.AttentionCount);
        Assert.Contains("Подозрительных признаков очистки: 1", ctx.CleanupVerdict());
    }

    [Fact]
    public void Clean_result_yields_calm_verdict()
    {
        var ctx = CreateContext(new AuditResult());

        Assert.Contains("не обнаружено", ctx.CleanupVerdict());
        Assert.Equal(0, ctx.SuspiciousCount);
    }

    [Fact]
    public void Case_metadata_and_hashes_are_passed_through()
    {
        var ctx = CreateContext(SampleResult());

        Assert.Equal("Д-42", ctx.Case.CaseNumber);
        Assert.Empty(ctx.UsbExecutableHashes);
        Assert.NotNull(ctx.Exfiltration);
        Assert.NotNull(ctx.Mitre);
    }

    [Fact]
    public void Policy_summary_reflects_explicit_policy()
    {
        var policy = DevicePolicyEvaluator.Parse("""
            { "blocked": [ { "serial": "CORP-1" } ] }
            """);

        var ctx = CreateContext(SampleResult(), policy);

        Assert.True(ctx.PolicySummary.PolicyDefined);
        Assert.True(ctx.PolicySummary.HasViolations);
    }

    [Fact]
    public void Verdict_methods_always_produce_text()
    {
        var ctx = CreateContext(SampleResult());

        Assert.False(string.IsNullOrWhiteSpace(ctx.ActivityVerdict()));
        Assert.False(string.IsNullOrWhiteSpace(ctx.TransferVerdict()));
        Assert.False(string.IsNullOrWhiteSpace(ctx.ScanDurationText));
        Assert.Contains("2 мин.", ctx.ScanDurationText);
    }

    [Fact]
    public void Findings_are_sorted_by_severity_then_time()
    {
        var ctx = CreateContext(SampleResult());

        Assert.Equal(ctx.CleanupFindings.OrderByDescending(x => x.TimestampUtc).Select(x => x.Finding),
            ctx.CleanupFindings.Select(x => x.Finding));
        Assert.All(ctx.SuspiciousFindings, x => Assert.True(x.IsSuspicious));
    }

    [Fact]
    public void Device_activity_is_cached_between_requests()
    {
        var result = SampleResult();
        var ctx = CreateContext(result);
        var device = result.Devices[0];

        Assert.Same(ctx.GetActivity(device), ctx.GetActivity(device));
    }
}
