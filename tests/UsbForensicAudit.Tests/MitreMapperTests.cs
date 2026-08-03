using System;
using System.Linq;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Сопоставление находок с MITRE ATT&CK: техника попадает в вывод только при
/// наличии конкретной опоры (носитель, вынос, очистка), очистка журналов
/// выделяется отдельной подтехникой, и секция появляется в HTML-отчёте.
/// </summary>
public sealed class MitreMapperTests
{
    private static CleanupFinding Suspicious(string finding, string area = "", string details = "", string eventId = "") => new()
    {
        Assessment = "Suspicious",
        Severity = "High",
        Finding = finding,
        Area = area,
        Details = details,
        EventId = eventId
    };

    [Fact]
    public void Empty_audit_maps_no_techniques()
    {
        var assessment = MitreMapper.Map(new AuditResult());

        Assert.False(assessment.HasFindings);
        Assert.Contains("не выявлено", assessment.Verdict());
    }

    [Fact]
    public void Removable_media_maps_T1091()
    {
        var result = new AuditResult();
        result.Devices.Add(new UsbDeviceRecord { DeviceKind = DeviceKindResolver.Storage });

        var ids = MitreMapper.Map(result).Findings.Select(x => x.Technique.Id).ToArray();

        Assert.Contains("T1091", ids);
    }

    [Fact]
    public void Outbound_files_map_T1052_001()
    {
        var result = new AuditResult();
        var device = new UsbDeviceRecord { DeviceKind = DeviceKindResolver.Storage };
        device.CopyIndications.Add(new CopyIndication
        {
            FileName = "plan.docx",
            Direction = CopyDirection.ToDevice,
            Confidence = "High"
        });
        result.Devices.Add(device);

        var ids = MitreMapper.Map(result).Findings.Select(x => x.Technique.Id).ToArray();

        Assert.Contains("T1052.001", ids);
    }

    [Fact]
    public void Suspicious_cleanup_maps_indicator_removal_and_log_clearing()
    {
        var result = new AuditResult();
        result.CleanupFindings.Add(Suspicious("Очищен журнал безопасности", area: "Security", details: "Событие 1102"));

        var ids = MitreMapper.Map(result).Findings.Select(x => x.Technique.Id).ToArray();

        Assert.Contains("T1070", ids);
        Assert.Contains("T1070.001", ids);
    }

    [Fact]
    public void Cleanup_without_log_clearing_does_not_map_subtechnique()
    {
        var result = new AuditResult();
        result.CleanupFindings.Add(Suspicious("Удалён раздел реестра USBSTOR"));

        var ids = MitreMapper.Map(result).Findings.Select(x => x.Technique.Id).ToArray();

        Assert.Contains("T1070", ids);
        Assert.DoesNotContain("T1070.001", ids);
    }

    [Fact]
    public void Event_id_1102_maps_log_clearing_even_without_keywords()
    {
        var result = new AuditResult();
        result.CleanupFindings.Add(Suspicious("Аномалия журнала", area: "Security", eventId: "1102"));

        var ids = MitreMapper.Map(result).Findings.Select(x => x.Technique.Id).ToArray();

        Assert.Contains("T1070.001", ids);
    }

    [Fact]
    public void Bare_number_1102_in_text_does_not_map_log_clearing()
    {
        var result = new AuditResult();
        // 1102 как часть ID записи/пути, без слов про очистку журнала — не вердикт.
        result.CleanupFindings.Add(Suspicious("Удалён раздел реестра", details: "record 11021 offset 41102"));

        var ids = MitreMapper.Map(result).Findings.Select(x => x.Technique.Id).ToArray();

        Assert.Contains("T1070", ids);
        Assert.DoesNotContain("T1070.001", ids);
    }

    [Fact]
    public void Html_report_includes_mitre_section()
    {
        var result = new AuditResult
        {
            StartedAtUtc = DateTimeOffset.Parse("2026-01-01T10:00:00Z"),
            FinishedAtUtc = DateTimeOffset.Parse("2026-01-01T10:05:00Z")
        };
        result.Devices.Add(new UsbDeviceRecord { DeviceKind = DeviceKindResolver.Storage });

        var html = ForensicReportBuilder.BuildHtml(result);

        Assert.Contains("id=\"mitre\"", html, StringComparison.Ordinal);
        Assert.Contains("T1091", html, StringComparison.Ordinal);
        Assert.Contains("attack.mitre.org", html, StringComparison.Ordinal);
    }
}
