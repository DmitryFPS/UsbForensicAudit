using System.IO;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class ExternalUtilityColumnNormalizerExtendedTests
{
    [Fact]
    public void LooksMisaligned_detects_vid_in_manufacturer_column()
    {
        var values = new Dictionary<string, string>
        {
            ["VID"] = "0E0F",
            ["Производитель"] = "0003",
            ["PID"] = "VMware, Inc."
        };

        Assert.True(ExternalUtilityColumnNormalizer.LooksMisaligned(values));
    }

    [Fact]
    public void FindConnectionDate_returns_first_date_field_in_priority_order()
    {
        var values = new Dictionary<string, string>
        {
            ["Первое подключение"] = "01.01.1970 03:00",
            ["Установка"] = "15.03.2024 12:00"
        };

        Assert.Equal("01.01.1970 03:00", ExternalUtilityColumnNormalizer.FindConnectionDate(values));
    }

    [Fact]
    public void NormalizeHeaders_trims_and_expands()
    {
        var headers = ExternalUtilityColumnNormalizer.NormalizeHeaders(["  VID ", "Первое подключ..."]);
        Assert.Contains("Первое подключение", headers);
    }

    [Fact]
    public void MapRawRowValues_aligns_cells_to_headers()
    {
        var values = ExternalUtilityColumnNormalizer.MapRawRowValues(
            ["Vendor ID", "Product ID"],
            ["0951", "1666"]);

        Assert.Equal("0951", values["Vendor ID"]);
        Assert.Equal("1666", values["Product ID"]);
    }
}

public class ProcmonCsvParserExtendedTests
{
    [Fact]
    public void ParseFile_returns_empty_for_missing_file()
    {
        Assert.Empty(ProcmonCsvParser.ParseFile(Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.csv")));
    }
}
