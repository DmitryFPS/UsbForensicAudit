using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Правила алертов фонового мониторинга: неизвестные устройства, нарушения
/// политики, дедупликация повторов и извлечение серийника из DeviceId.
/// </summary>
public sealed class LiveMonitorRulesTests
{
    private static LiveUsbDevice Device(string serial = "CORP-1", string vid = "0951", string pid = "1666") => new()
    {
        DeviceName = "Kingston DataTraveler",
        DeviceId = $@"USB\VID_{vid}&PID_{pid}\{serial}",
        Vid = vid,
        Pid = pid,
        StableKey = $"{vid}:{pid}:{serial}"
    };

    [Fact]
    public void Serial_is_extracted_from_device_id_tail()
    {
        Assert.Equal("CORP-1", LiveMonitorRules.ToPolicyRecord(Device()).Serial);
    }

    [Fact]
    public void Generated_instance_id_tail_is_not_a_serial()
    {
        var device = Device();
        device.DeviceId = @"USB\VID_0951&PID_1666\5&2f4a&0&2";

        Assert.Equal("", LiveMonitorRules.ToPolicyRecord(device).Serial);
    }

    [Fact]
    public void Unknown_device_raises_alert_once()
    {
        var alerted = new HashSet<string>(StringComparer.Ordinal);
        var unknown = new[] { Device() };

        var first = LiveMonitorRules.Evaluate(unknown, unknown, DevicePolicy.None, alerted);
        var second = LiveMonitorRules.Evaluate(unknown, unknown, DevicePolicy.None, alerted);

        Assert.Single(first);
        Assert.Equal(MonitorAlertKind.UnknownDevice, first[0].Kind);
        Assert.Empty(second);
    }

    [Fact]
    public void Blocked_device_raises_policy_alert()
    {
        var policy = DevicePolicyEvaluator.Parse("""
            { "blocked": [ { "serial": "CORP-1" } ] }
            """);
        var snapshot = new[] { Device() };

        var alerts = LiveMonitorRules.Evaluate(snapshot, [], policy, new HashSet<string>(StringComparer.Ordinal));

        Assert.Single(alerts);
        Assert.Equal(MonitorAlertKind.PolicyViolation, alerts[0].Kind);
        Assert.Contains("чёрном списке", alerts[0].Details);
    }

    [Fact]
    public void Empty_policy_yields_no_policy_alerts()
    {
        var alerts = LiveMonitorRules.Evaluate(
            [Device()], [], DevicePolicy.None, new HashSet<string>(StringComparer.Ordinal));

        Assert.DoesNotContain(alerts, x => x.Kind == MonitorAlertKind.PolicyViolation);
    }
}
