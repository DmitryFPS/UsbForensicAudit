using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class ReferenceImageTraceTests
{
    [Fact]
    public void Clean_install_says_no_image_was_used()
    {
        var trace = new ReferenceImageTrace();

        Assert.False(trace.WasDeployedFromImage);
        Assert.Contains("устанавливали на этой машине", trace.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void Clone_tag_is_decisive_evidence_of_an_image()
    {
        var trace = new ReferenceImageTrace { PreparedAtUtc = new DateTimeOffset(2026, 7, 20, 8, 0, 0, TimeSpan.Zero) };
        trace.Add("Отметка клонирования образа", "CloneTag присутствует", isDecisive: true);

        Assert.True(trace.WasDeployedFromImage);
        Assert.Contains("развёрнута из готового образа", trace.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void Indirect_signal_alone_does_not_claim_an_image()
    {
        var trace = new ReferenceImageTrace();
        trace.Add("Следы виртуальной машины в истории", "VMware", isDecisive: false);

        Assert.False(trace.WasDeployedFromImage);
        Assert.Contains("могла быть развёрнута", trace.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void Devices_known_before_the_image_was_prepared_belong_to_its_builder()
    {
        var trace = new ReferenceImageTrace { PreparedAtUtc = new DateTimeOffset(2026, 7, 20, 8, 0, 0, TimeSpan.Zero) };

        Assert.True(trace.PredatesDeployment(new DateTimeOffset(2026, 7, 19, 8, 0, 0, TimeSpan.Zero)));
        Assert.False(trace.PredatesDeployment(new DateTimeOffset(2026, 7, 21, 8, 0, 0, TimeSpan.Zero)));
        Assert.False(trace.PredatesDeployment(null));
    }

    [Fact]
    public void Without_a_preparation_date_nothing_is_attributed_to_the_image()
    {
        var trace = new ReferenceImageTrace();
        trace.Add("Образ обобщён утилитой sysprep", "GeneralizationState = 7", isDecisive: true);

        Assert.False(trace.PredatesDeployment(new DateTimeOffset(1990, 1, 1, 0, 0, 0, TimeSpan.Zero)));
    }

    [Theory]
    [InlineData("Sun Jul 27 06:33:56 2026", "2026-07-27T06:33:56+00:00")]
    [InlineData("Mon Jan  5 09:00:00 2026", "2026-01-05T09:00:00+00:00")]
    [InlineData("2026-07-27 06:33:56", "2026-07-27T06:33:56+00:00")]
    public void Clone_tag_date_is_read_in_the_format_sysprep_writes(string value, string expected)
    {
        var parsed = ReferenceImageDetector.ParseCloneTagDate(value);

        Assert.NotNull(parsed);
        Assert.Equal(DateTimeOffset.Parse(expected), parsed!.Value);
    }

    [Fact]
    public void Unreadable_clone_tag_is_not_guessed()
    {
        Assert.Null(ReferenceImageDetector.ParseCloneTagDate(""));
        Assert.Null(ReferenceImageDetector.ParseCloneTagDate("не дата"));
    }

    [Fact]
    public void Records_predating_the_image_are_taken_off_the_users_account()
    {
        var result = new AuditResult
        {
            ReferenceImage = new ReferenceImageTrace
            {
                PreparedAtUtc = new DateTimeOffset(2026, 7, 20, 8, 0, 0, TimeSpan.Zero)
            }
        };
        result.ReferenceImage.Add("Отметка клонирования образа", "CloneTag", isDecisive: true);
        result.Devices.Add(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_VMware\image-era",
            FirstConnectedUtc = new DateTimeOffset(2026, 7, 10, 8, 0, 0, TimeSpan.Zero)
        });
        result.Devices.Add(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk\2412&0",
            FirstConnectedUtc = new DateTimeOffset(2026, 7, 25, 8, 0, 0, TimeSpan.Zero)
        });

        AuditOrchestrator.ApplyReferenceImageAttribution(result);

        Assert.True(result.Devices[0].InheritedFromReferenceImage);
        Assert.Contains("сборщик образа", result.Devices[0].UserMeaning, StringComparison.Ordinal);
        Assert.False(result.Devices[1].InheritedFromReferenceImage);
        Assert.Contains(result.SourceWarnings, x => x.Contains("эталонного образа", StringComparison.Ordinal));
    }
}
