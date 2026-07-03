using System.IO;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class ProcmonCsvParserTests
{
    [Fact]
    public void ToSourceHits_finds_enum_usb_and_mounted_devices_for_vid_pid()
    {
        var csvPath = WriteSampleCsv(
            """
            "Time of Day","Process Name","PID","Operation","Path","Result","Detail"
            "12:01:02.1234567","USBDetector.exe","4242","RegQueryValue","HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_0E0F&PID_0003\0001","SUCCESS","Length: 12"
            "12:01:02.2345678","USBDetector.exe","4242","RegOpenKey","HKLM\SYSTEM\MountedDevices","SUCCESS","Desired Access: Read"
            "12:01:02.3456789","notepad.exe","1111","RegQueryValue","HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_0E0F&PID_0003\0001","SUCCESS",""
            """);

        var row = new ExternalUtilityRow
        {
            SectionTitle = "Другие следы",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string>
            {
                ["VID"] = "0E0F",
                ["PID"] = "0003",
                ["Производитель"] = "VMware, Inc."
            },
            PrimaryText = "VMware"
        };
        var identifier = ExternalUtilityIdentifierParser.Parse(row);
        var events = ProcmonCsvParser.ParseFile(csvPath);
        var hits = ProcmonCsvParser.ToSourceHits(events, row, identifier, "USBDetector.exe");

        Assert.True(events.Count >= 2);
        Assert.NotEmpty(hits);
        Assert.All(hits, hit => Assert.True(hit.IsProcmonEvidence));
        Assert.Contains(hits, hit => hit.RegistryPath.Contains("Enum\\USB", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(hits, hit => hit.RegistryPath.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(hits, hit => hit.RegistryPath.Contains("notepad", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void MergeProcmonHits_prefers_procmon_and_deduplicates_paths()
    {
        var baseHits = new List<ExternalUtilitySourceHit>
        {
            new()
            {
                Title = "Enum\\USB",
                RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_0E0F&PID_0003",
                Found = true,
                ResultText = "найдено трассировкой реестра",
                LikelyUsbDetectorSource = true
            }
        };

        var procmonHits = new List<ExternalUtilitySourceHit>
        {
            new()
            {
                Title = "Procmon: Enum\\USB",
                RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_0E0F&PID_0003\0001",
                Found = true,
                ResultText = "RegQueryValue → прямой ключ реестра USB",
                LikelyUsbDetectorSource = true,
                IsProcmonEvidence = true,
                Operation = "RegQueryValue",
                ObservedAtUtc = DateTimeOffset.UtcNow,
                EvidenceRank = 300
            }
        };

        var merged = ExternalUtilitySourceCorrelator.MergeProcmonHits(baseHits, procmonHits);
        Assert.Equal(1, merged.Count(x => x.IsProcmonEvidence));
        Assert.StartsWith("Procmon:", merged[0].Title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Assess_with_procmon_adds_hard_evidence_formulation()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Другие следы",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string>
            {
                ["VID"] = "0E0F",
                ["PID"] = "0003"
            },
            PrimaryText = "VMware"
        };

        var procmonHits = new List<ExternalUtilitySourceHit>
        {
            new()
            {
                Title = "Procmon: MountedDevices",
                RegistryPath = @"HKLM\SYSTEM\MountedDevices",
                Found = true,
                ResultText = "RegOpenKey → косвенный ключ Windows; совпадение с VID/PID строки; Result=SUCCESS",
                LikelyUsbDetectorSource = true,
                IsProcmonEvidence = true,
                Operation = "RegOpenKey",
                ObservedAtUtc = DateTimeOffset.UtcNow,
                EvidenceRank = 280
            }
        };

        var assessment = ExternalUtilityRowExplainer.Assess(
            row,
            audit: null,
            procmonHits,
            procmonSessionDirectory: @"C:\Temp\procmon-test",
            procmonSummaryForReport: "Procmon test summary");

        Assert.True(assessment.HasProcmonEvidence);
        Assert.Contains("Procmon", assessment.VerdictTitle, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("Procmon test summary", assessment.ReportConclusionProcmon);
        Assert.Contains("PROCMON", assessment.SourceChecksText, StringComparison.OrdinalIgnoreCase);
    }

    private static string WriteSampleCsv(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"procmon-test-{Guid.NewGuid():N}.csv");
        File.WriteAllText(path, content, Encoding.UTF8);
        return path;
    }
}
