using System;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Политика «свой/чужой»: разбор JSON, решения по устройству и вердикт сводки,
/// плюс попадание секции в HTML-отчёт.
/// </summary>
public sealed class DevicePolicyTests
{
    private static UsbDeviceRecord External(string vid, string pid, string serial) => new()
    {
        Vid = vid,
        Pid = pid,
        Serial = serial,
        Externality = DeviceExternality.ExternalMedia,
        DeviceInstanceId = $@"USBSTOR\Disk&Ven\{serial}"
    };

    [Fact]
    public void Blocklist_takes_priority_over_allowlist()
    {
        var policy = DevicePolicyEvaluator.Parse("""
            {
              "allowlistEnforced": true,
              "allowed": [ { "vid": "0951" } ],
              "blocked": [ { "vid": "0951", "pid": "1666", "serial": "BAD" } ]
            }
            """);

        Assert.Equal(DevicePolicyDecision.Blocked, policy.Decide(External("0951", "1666", "BAD")));
        Assert.Equal(DevicePolicyDecision.Approved, policy.Decide(External("0951", "1666", "GOOD")));
    }

    [Fact]
    public void Allowlist_enforced_flags_unlisted_device()
    {
        var policy = DevicePolicyEvaluator.Parse("""
            { "allowlistEnforced": true, "allowed": [ { "serial": "CORP-1" } ] }
            """);

        Assert.Equal(DevicePolicyDecision.Approved, policy.Decide(External("1", "2", "CORP-1")));
        Assert.Equal(DevicePolicyDecision.Unlisted, policy.Decide(External("1", "2", "STRANGER")));
    }

    [Fact]
    public void Without_enforcement_unknown_device_is_not_a_violation()
    {
        var policy = DevicePolicyEvaluator.Parse("""
            { "allowlistEnforced": false, "blocked": [ { "serial": "BAD" } ] }
            """);

        Assert.Equal(DevicePolicyDecision.NotEvaluated, policy.Decide(External("1", "2", "OTHER")));
    }

    [Fact]
    public void Empty_or_blank_json_yields_empty_policy()
    {
        Assert.True(DevicePolicyEvaluator.Parse("").IsEmpty);
        Assert.True(DevicePolicyEvaluator.Parse("   ").IsEmpty);
    }

    [Fact]
    public void Summary_reports_violations()
    {
        var result = new AuditResult();
        result.Devices.Add(External("0951", "1666", "BAD"));
        result.Devices.Add(External("0951", "1666", "GOOD"));
        var policy = DevicePolicyEvaluator.Parse("""
            {
              "allowlistEnforced": true,
              "allowed": [ { "serial": "GOOD" } ],
              "blocked": [ { "serial": "BAD" } ]
            }
            """);

        var summary = DevicePolicyEvaluator.Evaluate(result, policy);

        Assert.True(summary.HasViolations);
        Assert.Equal(1, summary.BlockedCount);
        Assert.Equal(1, summary.ApprovedCount);
        Assert.Contains("Нарушения политики устройств", summary.Verdict());
    }

    [Fact]
    public void No_policy_summary_is_neutral()
    {
        var summary = DevicePolicyEvaluator.Evaluate(new AuditResult(), DevicePolicy.None);

        Assert.False(summary.PolicyDefined);
        Assert.False(summary.HasViolations);
        Assert.Contains("не задана", summary.Verdict());
    }

    [Fact]
    public void Html_report_includes_policy_section_when_defined()
    {
        var result = new AuditResult
        {
            StartedAtUtc = DateTimeOffset.Parse("2026-01-01T10:00:00Z"),
            FinishedAtUtc = DateTimeOffset.Parse("2026-01-01T10:05:00Z")
        };
        result.Devices.Add(External("0951", "1666", "BAD"));
        var policy = DevicePolicyEvaluator.Parse("""
            { "allowlistEnforced": true, "blocked": [ { "serial": "BAD" } ] }
            """);

        var html = ForensicReportBuilder.BuildHtml(result, policy: policy);

        Assert.Contains("id=\"policy\"", html, StringComparison.Ordinal);
        Assert.Contains("Соответствие политике устройств", html, StringComparison.Ordinal);
        Assert.Contains("чёрный список", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_report_hides_policy_section_when_not_defined()
    {
        var result = new AuditResult
        {
            StartedAtUtc = DateTimeOffset.Parse("2026-01-01T10:00:00Z"),
            FinishedAtUtc = DateTimeOffset.Parse("2026-01-01T10:05:00Z")
        };

        var html = ForensicReportBuilder.BuildHtml(result, policy: DevicePolicy.None);

        Assert.DoesNotContain("id=\"policy\"", html, StringComparison.Ordinal);
    }
}
