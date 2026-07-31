using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Артефакт со штампом раньше установки Windows выглядит как ошибка программы
/// или как доказательство работы за машиной до установки системы. Ни то, ни
/// другое не верно: у Shimcache штамп — это время изменения файла.
/// </summary>
public class PreInstallArtifactExplainerTests
{
    [Fact]
    public void Shimcache_record_older_than_the_installation_gets_an_explanation()
    {
        var result = BuildResult(new EvidenceRecord
        {
            TimestampUtc = new DateTimeOffset(2021, 11, 29, 17, 36, 29, TimeSpan.Zero),
            Source = "Shimcache/AppCompatCache Parsed",
            Summary = @"Shimcache path: D:\Софт\regedit\USBOblivion64.exe"
        });

        PreInstallArtifactExplainer.Explain(result);

        var explanation = result.Evidence[0].UserExplanation;
        Assert.Contains("старше установки Windows", explanation);
        Assert.Contains("время последнего изменения файла", explanation);
        Assert.Contains(result.SourceWarnings, x => x.Contains("раньше установки Windows"));
    }

    [Fact]
    public void Record_newer_than_the_reference_image_says_the_image_does_not_explain_it()
    {
        var result = BuildResult(new EvidenceRecord
        {
            TimestampUtc = new DateTimeOffset(2025, 5, 29, 11, 27, 4, TimeSpan.Zero),
            Source = "Shimcache/AppCompatCache Parsed",
            Summary = @"Shimcache path: D:\Софт\regedit\USBDetector.exe"
        });
        result.ReferenceImage = new ReferenceImageTrace
        {
            PreparedAtUtc = new DateTimeOffset(2024, 6, 22, 12, 6, 16, TimeSpan.Zero)
        };

        PreInstallArtifactExplainer.Explain(result);

        Assert.Contains("новее подготовки эталонного образа", result.Evidence[0].UserExplanation);
    }

    [Fact]
    public void Event_log_record_is_not_explained_away_by_a_file_timestamp()
    {
        var result = BuildResult(new EvidenceRecord
        {
            TimestampUtc = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            Source = "Microsoft-Windows-Kernel-PnP/Configuration",
            Summary = "Kernel-PnP 400"
        });

        PreInstallArtifactExplainer.Explain(result);

        Assert.Equal("", result.Evidence[0].UserExplanation);
    }

    [Fact]
    public void Record_after_the_installation_is_left_alone()
    {
        var result = BuildResult(new EvidenceRecord
        {
            TimestampUtc = new DateTimeOffset(2026, 7, 30, 10, 0, 0, TimeSpan.Zero),
            Source = "Shimcache/AppCompatCache Parsed",
            Summary = @"Shimcache path: C:\Windows\System32\notepad.exe"
        });

        PreInstallArtifactExplainer.Explain(result);

        Assert.Equal("", result.Evidence[0].UserExplanation);
    }

    private static AuditResult BuildResult(params EvidenceRecord[] evidence)
    {
        var result = new AuditResult
        {
            OsInstalledAtUtc = new DateTimeOffset(2026, 7, 27, 6, 36, 31, TimeSpan.Zero)
        };
        result.Evidence.AddRange(evidence);
        return result;
    }
}
