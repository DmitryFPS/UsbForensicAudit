using System.IO;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class ProcmonCompletenessTests
{
    [Fact]
    public void ToSourceHits_matches_process_name_without_extension()
    {
        var csvPath = WriteCsv(
            """
            "Time of Day","Process Name","PID","Operation","Path","Result","Detail"
            "12:01:02.1234567","USBDetector","4242","RegQueryValue","HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_0951&PID_1666\1","SUCCESS",""
            """);

        var row = new ExternalUtilityRow
        {
            SectionTitle = "Список",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["VID"] = "0951", ["PID"] = "1666" },
            PrimaryText = "Kingston"
        };
        var id = ExternalUtilityIdentifierParser.Parse(row);
        var hits = ProcmonCsvParser.ToSourceHits(ProcmonCsvParser.ParseFile(csvPath), row, id, "USBDetector.exe");
        Assert.NotEmpty(hits);
    }

    [Fact]
    public void ToSourceHits_main_section_uses_fallback_when_no_needle_match()
    {
        var csvPath = WriteCsv(
            """
            "Time of Day","Process Name","PID","Operation","Path","Result","Detail"
            "12:01:02.1234567","USBDetector.exe","4242","RegOpenKey","HKLM\SOFTWARE\Unrelated","SUCCESS",""
            """);

        var row = new ExternalUtilityRow
        {
            SectionTitle = "Основной список (реестр)",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["VID"] = "0951", ["PID"] = "1666" },
            PrimaryText = "Kingston"
        };
        var id = ExternalUtilityIdentifierParser.Parse(row);
        var hits = ProcmonCsvParser.ToSourceHits(ProcmonCsvParser.ParseFile(csvPath), row, id, "USBDetector.exe");
        Assert.Single(hits);
        Assert.Contains("Unrelated", hits[0].RegistryPath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseFile_parses_time_with_fractional_seconds()
    {
        var csvPath = WriteCsv(
            """
            "Time of Day","Process Name","PID","Operation","Path","Result","Detail"
            "23:59:59.1234567","USBDetector.exe","1","RegOpenKey","HKLM\SYSTEM\MountedDevices","SUCCESS",""
            """);

        var events = ProcmonCsvParser.ParseFile(csvPath);
        Assert.Single(events);
        Assert.Equal(23, events[0].Timestamp.Hour);
    }

    [Fact]
    public void ToCore_exports_vendor_database()
    {
        var data = new UsbVendorDatabaseData();
        data.Vendors["0951"] = "Kingston";
        var core = UsbVendorDatabaseParser.ToCore(data);
        Assert.Equal("Kingston", core.Vendors["0951"]);
    }

    private static string WriteCsv(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"procmon-full-{Guid.NewGuid():N}.csv");
        File.WriteAllText(path, content, Encoding.UTF8);
        return path;
    }
}

public class CleanerToolCatalogCompletenessTests
{
    [Theory]
    [InlineData("powershell.exe")]
    [InlineData("pwsh.dll")]
    [InlineData("dism.exe")]
    [InlineData("wmic bios")]
    public void Match_and_display_cover_system_tools(string text)
    {
        var pattern = CleanerToolCatalog.Match(text);
        Assert.NotNull(pattern);
        Assert.False(string.IsNullOrWhiteSpace(CleanerToolCatalog.DisplayName(pattern!)));
    }
}
