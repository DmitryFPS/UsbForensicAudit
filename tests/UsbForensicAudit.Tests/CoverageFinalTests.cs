using System.IO;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class ColumnNormalizerHeaderTests
{
    [Theory]
    [InlineData("Manufact...", "Производитель")]
    [InlineData("Model", "Модель")]
    [InlineData("Install date", "Установка")]
    [InlineData("Modified", "Модификация")]
    [InlineData("Vendor ID", "Vendor ID")]
    [InlineData("Product ID", "Product ID")]
    [InlineData("Device Name", "Device Name")]
    [InlineData("Serial", "Serial Number")]
    [InlineData("Last Plug/Unplug Date", "Модификация")]
    public void NormalizeHeaderName_expands_truncated_headers(string input, string expected)
    {
        Assert.Equal(expected, ExternalUtilityColumnNormalizer.NormalizeHeaderName(input));
    }

    [Fact]
    public void LooksMisaligned_true_when_date_column_contains_hex()
    {
        var values = new Dictionary<string, string>
        {
            ["VID"] = "0E0F",
            ["Производитель"] = "VMware, Inc.",
            ["PID"] = "0003",
            ["Установка"] = "0003"
        };

        Assert.True(ExternalUtilityColumnNormalizer.LooksMisaligned(values));
    }

    [Fact]
    public void MapRowValues_remaps_shifted_row_with_hex_in_manufacturer()
    {
        var values = ExternalUtilityColumnNormalizer.MapRowValues(
            ["VID", "Производитель", "PID", "Модель"],
            ["0E0F", "0003", "VMware, Inc.", "Virtual"]);

        Assert.True(values.ContainsKey("VID"));
        Assert.Equal("0E0F", values["VID"]);
    }
}

public class ProcmonParserFallbackTests
{
    [Fact]
    public void ToSourceHits_fallback_shows_indirect_reads_for_other_traces()
    {
        var csvPath = Path.Combine(Path.GetTempPath(), $"procmon-fb-{Guid.NewGuid():N}.csv");
        File.WriteAllText(csvPath,
            """
            "Time of Day","Process Name","PID","Operation","Path","Result","Detail"
            "12:00:00.0000000","USBDetector.exe","42","RegOpenKey","HKLM\SYSTEM\MountedDevices","SUCCESS",""
            """,
            Encoding.UTF8);

        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["VID"] = "FFFF", ["PID"] = "0001" },
            PrimaryText = "Test"
        };
        var id = ExternalUtilityIdentifierParser.Parse(row);
        var events = ProcmonCsvParser.ParseFile(csvPath);
        var hits = ProcmonCsvParser.ToSourceHits(events, row, id, "USBDetector.exe");

        Assert.NotEmpty(hits);
        Assert.Contains(hits, h => h.RegistryPath.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ParseFile_skips_non_registry_operations()
    {
        var csvPath = Path.Combine(Path.GetTempPath(), $"procmon-nr-{Guid.NewGuid():N}.csv");
        File.WriteAllText(csvPath,
            """
            "Time of Day","Process Name","PID","Operation","Path","Result","Detail"
            "12:00:00.0000000","USBDetector.exe","42","Process Profiling","USBDetector.exe","SUCCESS",""
            """,
            Encoding.UTF8);

        Assert.Empty(ProcmonCsvParser.ParseFile(csvPath));
    }
}

public class ExternalUtilityRowExplainerExtendedTests
{
    [Fact]
    public void ShortVerdict_returns_title()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["VID"] = "0E0F", ["PID"] = "0003" },
            PrimaryText = "VMware"
        };

        var title = ExternalUtilityRowExplainer.ShortVerdict(row, null);
        Assert.Contains("VMware", title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Explain_usbdeview_not_found_includes_vid_text()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Список устройств",
            UtilityName = "USBDeview",
            Values = new Dictionary<string, string> { ["Vendor ID"] = "0951", ["Product ID"] = "1666" },
            PrimaryText = "Kingston"
        };

        var text = ExternalUtilityRowExplainer.Explain(row, new AuditResult());
        Assert.Contains("0951/1666", text);
    }

    [Fact]
    public void Assess_usbdeview_without_vid_shows_parse_note()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Список устройств",
            UtilityName = "USBDeview",
            Values = new Dictionary<string, string> { ["Device Name"] = "Mystery device" },
            PrimaryText = "Mystery device"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, new AuditResult());
        Assert.Contains("Vendor ID", assessment.UsbDetectorNote, StringComparison.OrdinalIgnoreCase);
    }
}
