using System.IO;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class CompactVidPidParserTests
{
    [Theory]
    [InlineData(@"USB\VID_0951&PID_1666\001", "0951", "1666")]
    [InlineData("Vid_0E0FPid_0003", "0E0F", "0003")]
    public void ExtractVidPid_parses_standard_and_compact(string text, string vid, string pid)
    {
        var result = CompactVidPidParser.ExtractVidPid(text);
        Assert.Equal(vid, result.Vid);
        Assert.Equal(pid, result.Pid);
    }

    [Fact]
    public void BuildMatchTokens_yields_vid_pid_variants()
    {
        var tokens = CompactVidPidParser.BuildMatchTokens(@"VID_0951&PID_1666").ToArray();
        Assert.Contains("VID_0951", tokens);
        Assert.Contains("PID_1666", tokens);
        Assert.Contains("0951:1666", tokens);
    }
}

public class ExternalUtilitySectionCatalogTests
{
    [Fact]
    public void IsOtherTracesSection_detects_russian_title()
    {
        Assert.True(ExternalUtilitySectionCatalog.IsOtherTracesSection("Другие следы подключения устройств"));
        Assert.False(ExternalUtilitySectionCatalog.IsOtherTracesSection("Основной список"));
    }

    [Fact]
    public void GetInfo_returns_metadata_for_known_sections()
    {
        var other = ExternalUtilitySectionCatalog.GetInfo(ExternalUtilitySectionCatalog.OtherTracesSection);
        Assert.Contains("косвенные", other.Summary, StringComparison.OrdinalIgnoreCase);

        var main = ExternalUtilitySectionCatalog.GetInfo("Основной список (реестр)");
        Assert.Contains("Enum", main.TypicalSources, StringComparison.OrdinalIgnoreCase);
    }
}

public class ExternalUtilityRowKeyTests
{
    [Fact]
    public void Build_combines_utility_section_and_text()
    {
        var row = new ExternalUtilityRow
        {
            UtilityName = "USBDetector",
            SectionTitle = "Другие следы",
            PrimaryText = "VMware",
            Values = new Dictionary<string, string> { ["A"] = "B" }
        };

        var key = ExternalUtilityRowKey.Build(row);
        Assert.StartsWith("USBDetector|Другие следы|VMware|", key);
    }
}

public class ProcmonRegistryPathClassifierTests
{
    [Theory]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_Kingston", true, false)]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_0951&PID_1666", true, false)]
    [InlineData(@"HKLM\SYSTEM\MountedDevices", false, true)]
    [InlineData(@"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2", false, true)]
    public void Classify_marks_direct_and_indirect_sources(string path, bool direct, bool indirect)
    {
        var c = ProcmonRegistryPathClassifier.Classify(path);
        Assert.Equal(direct, c.IsDirectSource);
        Assert.Equal(indirect, c.IsIndirectSource);
    }
}

public class ProcmonNeedleMatcherTests
{
    [Fact]
    public void BuildNeedles_includes_vid_pid_and_primary_text()
    {
        var row = new ExternalUtilityRow
        {
            PrimaryText = "Kingston",
            Values = new Dictionary<string, string> { ["VID"] = "0951", ["PID"] = "1666" },
            UtilityName = "USBDeview",
            SectionTitle = "Список"
        };
        var id = ExternalUtilityIdentifierParser.Parse(row);
        var needles = ProcmonNeedleMatcher.BuildNeedles(row, id);

        Assert.Contains(needles, n => n.Contains("0951", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(needles, n => n.Contains("Kingston", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void MatchesPathOrDetail_finds_needle_in_path()
    {
        var needles = new[] { "VID_0E0F", "VMware" };
        Assert.True(ProcmonNeedleMatcher.MatchesPathOrDetail(
            @"HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_0E0F&PID_0003", null, needles));
    }
}

public class ProcmonReportBuilderTests
{
    [Fact]
    public void BuildSummary_describes_registry_read()
    {
        var row = new ExternalUtilityRow
        {
            UtilityName = "USBDetector",
            SectionTitle = "Другие следы",
            PrimaryText = "VMware",
            Values = new Dictionary<string, string>()
        };
        var id = ExternalUtilityIdentifierParser.Parse(new ExternalUtilityRow
        {
            Values = new Dictionary<string, string> { ["VID"] = "0E0F", ["PID"] = "0003" },
            PrimaryText = "VMware",
            UtilityName = "USBDetector",
            SectionTitle = "Другие следы"
        });
        var hits = new[]
        {
            new ExternalUtilitySourceHit
            {
                Title = "Procmon: MountedDevices",
                Operation = "RegQueryValue",
                RegistryPath = @"HKLM\SYSTEM\MountedDevices",
                Found = true,
                ResultText = "косвенный ключ Windows",
                ObservedAtUtc = DateTimeOffset.Parse("2024-06-01T12:00:00Z")
            }
        };

        var summary = ProcmonReportBuilder.BuildSummary(row, id, hits);
        Assert.Contains("Procmon", summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("MountedDevices", summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("не доказательство", summary, StringComparison.OrdinalIgnoreCase);
    }
}

public class DateDisplayTests
{
    [Fact]
    public void FormatMoscow_rejects_epoch_and_future()
    {
        Assert.Equal("нет точной даты", DateDisplay.FormatMoscow(DateTimeOffset.Parse("1970-01-01T00:00:00Z")));
        Assert.Equal("нет точной даты", DateDisplay.FormatMoscow(DateTimeOffset.UtcNow.AddYears(5)));
    }

    [Fact]
    public void FormatMoscow_formats_reliable_timestamp()
    {
        var text = DateDisplay.FormatMoscow(DateTimeOffset.Parse("2024-03-15T10:30:00Z"));
        Assert.Contains("МСК", text);
        Assert.Contains("2024", text);
    }

    [Fact]
    public void IsReliable_accepts_recent_dates()
    {
        Assert.True(DateDisplay.IsReliable(DateTimeOffset.Parse("2024-01-01T00:00:00Z")));
        Assert.False(DateDisplay.IsReliable(DateTimeOffset.Parse("1999-12-31T00:00:00Z")));
    }
}

public class CleanerToolCatalogTests
{
    [Theory]
    [InlineData("C:\\Tools\\USBDeview.exe", "usbdeview")]
    [InlineData("wevtutil cl Security", "wevtutil")]
    public void Match_finds_known_patterns(string text, string expected)
    {
        Assert.Equal(expected, CleanerToolCatalog.Match(text));
    }

    [Fact]
    public void DisplayName_localizes_patterns()
    {
        Assert.Equal("USBDeview", CleanerToolCatalog.DisplayName("usbdeview"));
        Assert.Contains("PowerShell", CleanerToolCatalog.DisplayName("powershell"));
    }

    [Fact]
    public void IsUsbForensicUtility_detects_forensic_tools_only()
    {
        Assert.True(CleanerToolCatalog.IsUsbForensicUtility("USBDeview"));
        Assert.False(CleanerToolCatalog.IsUsbForensicUtility("CCleaner"));
    }
}

public class AppPathsTests
{
    [Fact]
    public void DataDirectory_is_resolved_and_layout_description_is_non_empty()
    {
        var dir = AppPaths.DataDirectory;
        Assert.False(string.IsNullOrWhiteSpace(dir));
        Assert.True(Directory.Exists(dir) || AppPaths.IsPortableLayout == false);
        Assert.Contains("Данные", AppPaths.LayoutDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Tools_and_procmon_directories_live_under_data()
    {
        Assert.StartsWith(AppPaths.DataDirectory, AppPaths.ToolsDirectory, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith(AppPaths.DataDirectory, AppPaths.ProcmonDirectory, StringComparison.OrdinalIgnoreCase);
    }
}

public class ReportTextTests
{
    [Fact]
    public void ForDisplay_normalizes_plain_text()
    {
        var text = ReportText.ForDisplay("Kingston DataTraveler");
        Assert.Contains("Kingston", text);
    }

    [Fact]
    public void ForDisplayOrClean_falls_back_to_clean()
    {
        var text = ReportText.ForDisplayOrClean("Prefetch: USBDeview.exe");
        Assert.Contains("Prefetch", text, StringComparison.OrdinalIgnoreCase);
    }
}

public class LiveDeviceIdentityTests
{
    [Fact]
    public void StableKey_uses_vid_pid_and_serial()
    {
        var key = LiveDeviceIdentity.StableKey(@"USB\VID_0951&PID_1666\001", "0951", "1666");
        Assert.Contains("0951", key, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("1666", key, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("001", key, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExtractVidPid_parses_device_id()
    {
        var (vid, pid) = LiveDeviceIdentity.ExtractVidPid(@"USB\VID_0E0F&PID_0003\0001");
        Assert.Equal("0E0F", vid);
        Assert.Equal("0003", pid);
    }
}
