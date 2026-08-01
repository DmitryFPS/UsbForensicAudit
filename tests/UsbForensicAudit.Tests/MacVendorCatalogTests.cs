using System.IO;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// База изготовителей по префиксу аппаратного адреса: разбор файла,
/// поиск от длинного префикса к короткому и честные ответы, когда
/// изготовителя узнать нельзя.
/// </summary>
public sealed class MacVendorCatalogTests
{
    [Fact]
    public void Parse_reads_prefixes_and_skips_comments_and_garbage()
    {
        using var reader = new StringReader(string.Join("\n",
        [
            "# комментарий",
            "",
            "000001/24\tXerox Corporation",
            "001A2B3/28\tSmall Vendor",
            "001122334/36\tTiny Vendor",
            "строка без табуляции",
            "00/8\tслишком короткий префикс",
            "000001/24\tДубль первого — должен быть отброшен",
            "\tбез префикса"
        ]));

        var prefixes = MacVendorCatalog.Parse(reader);

        Assert.Equal(3, prefixes.Count);
        Assert.Equal("Xerox Corporation", prefixes["000001"]);
        Assert.Equal("Small Vendor", prefixes["001A2B3"]);
        Assert.Equal("Tiny Vendor", prefixes["001122334"]);
    }

    [Fact]
    public void Lookup_uses_embedded_catalog_and_normalizes_address_format()
    {
        Assert.True(MacVendorCatalog.Count > 0);
        Assert.Equal("Xerox Corporation", MacVendorCatalog.Lookup("00:00:01:12:34:56"));
        Assert.Equal("Xerox Corporation", MacVendorCatalog.Lookup("00-00-01-12-34-56"));
        Assert.Equal("Xerox Corporation", MacVendorCatalog.Lookup("000001123456"));
    }

    [Fact]
    public void Lookup_returns_empty_for_short_or_missing_address()
    {
        Assert.Equal("", MacVendorCatalog.Lookup(null));
        Assert.Equal("", MacVendorCatalog.Lookup(""));
        Assert.Equal("", MacVendorCatalog.Lookup("00:00"));
    }

    [Fact]
    public void Describe_explains_missing_and_locally_assigned_addresses()
    {
        Assert.Equal("аппаратный адрес неизвестен", MacVendorCatalog.Describe(""));
        Assert.Equal("аппаратный адрес неизвестен", MacVendorCatalog.Describe(null));
        Assert.Equal("Xerox Corporation", MacVendorCatalog.Describe("00:00:01:12:34:56"));
        // Второй бит первого октета: адрес назначен на месте, завода за ним нет.
        Assert.Contains("назначен на месте", MacVendorCatalog.Describe("02:00:00:AA:BB:CC"));
    }
}
