using System.IO;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class UsbVendorDatabaseParserTests
{
    [Fact]
    public void Parse_reads_usb_ids_format()
    {
        const string sample = """
            # comment
            0e0f  VMware, Inc.
            	0003  Virtual Mouse
            0951  Kingston Technology
            	1666  DataTraveler 3.0
            """;

        using var reader = new StringReader(sample);
        var data = UsbVendorDatabaseParser.Parse(reader);

        Assert.Equal("VMware, Inc.", data.Vendors["0E0F"]);
        Assert.Equal("Virtual Mouse", data.Products["0E0F"]["0003"]);
        Assert.Equal("Kingston Technology", data.Vendors["0951"]);
    }

    [Fact]
    public void Write_roundtrip_preserves_entries()
    {
        var data = new UsbVendorDatabaseData();
        data.Vendors["0951"] = "Kingston Technology";
        data.Products["0951"] = new Dictionary<string, string> { ["1666"] = "DataTraveler" };

        var builder = new StringBuilder();
        UsbVendorDatabaseParser.Write(new StringWriter(builder), data);
        var parsed = UsbVendorDatabaseParser.Parse(new StringReader(builder.ToString()));

        Assert.Equal("Kingston Technology", parsed.Vendors["0951"]);
        Assert.Equal("DataTraveler", parsed.Products["0951"]["1666"]);
    }

    [Fact]
    public void Merge_prefers_better_vendor_name()
    {
        var target = new UsbVendorDatabaseData();
        target.Vendors["0951"] = "Unknown";
        var source = new UsbVendorDatabaseData();
        source.Vendors["0951"] = "Kingston Technology";

        UsbVendorDatabaseParser.Merge(target, source, sourceWinsOnConflict: true);

        Assert.Equal("Kingston Technology", target.Vendors["0951"]);
    }
}
