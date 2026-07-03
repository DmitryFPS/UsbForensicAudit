using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class TimelineEnricherTests
{
    [Fact]
    public void Enrich_fills_user_explanation_for_prefetch()
    {
        var result = new AuditResult();
        result.Evidence.Add(new EvidenceRecord
        {
            Source = "Prefetch",
            Summary = "Prefetch содержит USB/Volume/drive индикаторы: TEST.PF"
        });

        new TimelineEnricher().Enrich(result);

        Assert.Contains("Prefetch", result.Evidence[0].UserExplanation, StringComparison.OrdinalIgnoreCase);
        Assert.False(string.IsNullOrWhiteSpace(result.Evidence[0].UserExplanationText));
    }

    [Fact]
    public void Enrich_classifies_jump_list_evidence()
    {
        var result = new AuditResult();
        result.Evidence.Add(new EvidenceRecord
        {
            Source = "JumpList",
            Summary = "Recent USB path"
        });

        new TimelineEnricher().Enrich(result);

        Assert.Equal("Пользовательская активность", result.Evidence[0].EvidenceCategory);
        Assert.Contains("Jump List", result.Evidence[0].UserExplanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Enrich_marks_support_artifact_devices_as_not_connected()
    {
        var result = new AuditResult();
        result.Devices.Add(new UsbDeviceRecord
        {
            VisualCategory = "SupportArtifact",
            DeviceInstanceId = "MountedDevices entry"
        });

        new TimelineEnricher().Enrich(result);

        Assert.False(result.Devices[0].IsCurrentlyConnected);
        Assert.Equal("NotApplicable", result.Devices[0].DisconnectDisplayKind);
    }

    [Fact]
    public void Enrich_classifies_amcache_and_setupapi()
    {
        var result = new AuditResult();
        result.Evidence.Add(new EvidenceRecord
        {
            Source = "Amcache",
            Summary = "USBDeview.exe"
        });
        result.Evidence.Add(new EvidenceRecord
        {
            Source = "setupapi.dev.log",
            Summary = "device install",
            EvidenceCategory = "Установка/инициализация"
        });

        new TimelineEnricher().Enrich(result);

        Assert.Equal("Запуск/исполнение", result.Evidence[0].EvidenceCategory);
        Assert.Contains("Amcache", result.Evidence[0].UserExplanation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("setupapi", result.Evidence[1].UserExplanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Enrich_sanitizes_source_warnings()
    {
        var result = new AuditResult();
        result.SourceWarnings.Add("  warning  with   spaces  ");

        new TimelineEnricher().Enrich(result);

        Assert.Equal("warning with spaces", result.SourceWarnings[0]);
    }

    [Fact]
    public void UserExplanationText_shows_mixed_russian_and_latin_terms()
    {
        var evidence = new EvidenceRecord
        {
            UserExplanation = "Prefetch: Windows сохранила след запуска программы с USB-путями."
        };

        Assert.Contains("Prefetch", evidence.UserExplanationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Windows", evidence.UserExplanationText, StringComparison.OrdinalIgnoreCase);
    }
}
