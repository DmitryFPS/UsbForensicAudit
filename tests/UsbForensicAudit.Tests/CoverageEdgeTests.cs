using System.IO;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class TextSanitizerExtendedTests
{
    [Fact]
    public void LooksLikeMojibake_detects_latin1_without_cyrillic()
    {
        Assert.True(TextSanitizer.LooksLikeMojibake("ÐÑÐÑÐ°ÐÐÑ ÑÐÐº"));
    }

    [Fact]
    public void NormalizeConsoleOutput_prefers_cp1251_for_cyrillic_bytes()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        var bytes = Encoding.GetEncoding(1251).GetBytes("Журнал USB");
        var text = TextSanitizer.NormalizeConsoleOutput(bytes);
        Assert.Contains("USB", text);
    }

    [Fact]
    public void Clean_truncates_to_max_length()
    {
        var longText = new string('A', 2000);
        Assert.Equal(100, TextSanitizer.Clean(longText, maxLength: 100).Length);
    }

    [Fact]
    public void NormalizeDisplay_returns_empty_for_unreadable_garbage()
    {
        Assert.Equal("", TextSanitizer.NormalizeDisplay("????????????????????????????"));
    }
}

public class LiveDeviceIdentityExtendedTests
{
    [Fact]
    public void ExtractSerial_strips_trailing_amp_zero()
    {
        Assert.Equal("ABC", LiveDeviceIdentity.ExtractSerial(@"USB\VID_0951&PID_1666\ABC&0"));
    }

    [Fact]
    public void NormalizeDeviceId_unifies_slashes()
    {
        var normalized = LiveDeviceIdentity.NormalizeDeviceId(@"usb\\vid_0951");
        Assert.Contains(@"USB\VID_0951", normalized);
    }
}

public class ProcmonParserEdgeTests
{
    [Fact]
    public void ParseFile_skips_blank_lines_and_empty_csv()
    {
        var path = Path.Combine(Path.GetTempPath(), $"procmon-edge-{Guid.NewGuid():N}.csv");
        File.WriteAllText(path, "Time of Day,Process Name,PID,Operation,Path,Result\n\n");
        Assert.Empty(ProcmonCsvParser.ParseFile(path));
    }

    [Fact]
    public void ParseFile_parses_doubled_quotes_in_csv()
    {
        var path = Path.Combine(Path.GetTempPath(), $"procmon-q-{Guid.NewGuid():N}.csv");
        File.WriteAllText(path,
            "\"Time of Day\",\"Process Name\",\"PID\",\"Operation\",\"Path\",\"Result\",\"Detail\"\n" +
            "\"12:00:00.0000000\",\"USBDetector.exe\",\"42\",\"RegOpenKey\",\"HKLM\\SYSTEM\\MountedDevices\",\"SUCCESS\",\"say \"\"hello\"\"\"\n");
        var events = ProcmonCsvParser.ParseFile(path);
        Assert.Single(events);
        Assert.Contains("hello", events[0].Detail);
    }
}

public class ExternalUtilityRowExplainerProcmonOriginTests
{
    [Fact]
    public void Assess_procmon_updates_probable_origin()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["VID"] = "0E0F", ["PID"] = "0003" },
            PrimaryText = "VMware"
        };
        var procmonHits = new List<ExternalUtilitySourceHit>
        {
            new()
            {
                Title = "Procmon: Enum\\USB",
                RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_0E0F&PID_0003",
                Found = true,
                ResultText = "RegQueryValue → прямой ключ реестра USB",
                IsProcmonEvidence = true,
                Operation = "RegQueryValue",
                ObservedAtUtc = DateTimeOffset.UtcNow,
                EvidenceRank = 300
            }
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, null, procmonHits, @"C:\temp", "summary");
        Assert.Contains("Procmon:", assessment.ProbableOrigin, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RegQueryValue", assessment.ProbableOrigin, StringComparison.OrdinalIgnoreCase);
    }
}
