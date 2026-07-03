using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

internal sealed class UsbVendorDatabaseData
{
    public Dictionary<string, string> Vendors { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, Dictionary<string, string>> Products { get; } = new(StringComparer.OrdinalIgnoreCase);
}

internal static class UsbVendorDatabaseParser
{
    private static readonly Regex VendorLineRegex = new(
        @"^(?<vid>[0-9A-Fa-f]{4})\s{1,}(?<name>.+)$",
        RegexOptions.Compiled);

    private static readonly Regex ProductLineRegex = new(
        @"^\t(?<pid>[0-9A-Fa-f]{4})\s{1,}(?<name>.+)$",
        RegexOptions.Compiled);

    public static UsbVendorDatabaseData Parse(TextReader reader)
    {
        var data = new UsbVendorDatabaseData();
        string? currentVid = null;

        while (reader.ReadLine() is { } rawLine)
        {
            var line = rawLine.TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
            {
                continue;
            }

            var vendorMatch = VendorLineRegex.Match(line);
            if (vendorMatch.Success)
            {
                currentVid = vendorMatch.Groups["vid"].Value.ToUpperInvariant();
                data.Vendors[currentVid] = vendorMatch.Groups["name"].Value.Trim();
                continue;
            }

            if (currentVid is null)
            {
                continue;
            }

            var productMatch = ProductLineRegex.Match(line);
            if (!productMatch.Success)
            {
                continue;
            }

            if (!data.Products.TryGetValue(currentVid, out var pidMap))
            {
                pidMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                data.Products[currentVid] = pidMap;
            }

            pidMap[productMatch.Groups["pid"].Value.ToUpperInvariant()] =
                productMatch.Groups["name"].Value.Trim();
        }

        return data;
    }

    public static UsbVendorDatabaseData ParseFile(string path)
    {
        using var reader = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return Parse(reader);
    }

    public static void Write(TextWriter writer, UsbVendorDatabaseData data)
    {
        writer.WriteLine("# USB vendor/product database (usb.ids format)");
        writer.WriteLine("# Merged for UsbForensicAudit — embedded in application");
        writer.WriteLine("# Sources: USBDetector base + linux-usb.org usb.ids");
        writer.WriteLine();

        foreach (var vendor in data.Vendors.OrderBy(x => ParseHex(x.Key)))
        {
            writer.WriteLine($"{vendor.Key.ToLowerInvariant()}  {vendor.Value}");
            if (!data.Products.TryGetValue(vendor.Key, out var products))
            {
                continue;
            }

            foreach (var product in products.OrderBy(x => ParseHex(x.Key)))
            {
                writer.WriteLine($"\t{product.Key.ToLowerInvariant()}  {product.Value}");
            }
        }
    }

    public static void Merge(UsbVendorDatabaseData target, UsbVendorDatabaseData source, bool sourceWinsOnConflict)
    {
        foreach (var (vid, vendorName) in source.Vendors)
        {
            if (!target.Vendors.TryGetValue(vid, out var existingVendor))
            {
                target.Vendors[vid] = vendorName;
            }
            else if (sourceWinsOnConflict)
            {
                target.Vendors[vid] = ChooseBetterName(existingVendor, vendorName, preferSecond: true);
            }
            else
            {
                target.Vendors[vid] = ChooseBetterName(existingVendor, vendorName, preferSecond: false);
            }
        }

        foreach (var (vid, sourceProducts) in source.Products)
        {
            if (!target.Products.TryGetValue(vid, out var targetProducts))
            {
                target.Products[vid] = new Dictionary<string, string>(sourceProducts, StringComparer.OrdinalIgnoreCase);
                continue;
            }

            foreach (var (pid, productName) in sourceProducts)
            {
                if (!targetProducts.TryGetValue(pid, out var existingProduct))
                {
                    targetProducts[pid] = productName;
                }
                else if (sourceWinsOnConflict)
                {
                    targetProducts[pid] = ChooseBetterName(existingProduct, productName, preferSecond: true);
                }
                else
                {
                    targetProducts[pid] = ChooseBetterName(existingProduct, productName, preferSecond: false);
                }
            }
        }
    }

    internal static UsbVendorDatabaseCore ToCore(UsbVendorDatabaseData data) =>
        new(data.Vendors, data.Products);

    private static int ParseHex(string value) =>
        int.Parse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private static string ChooseBetterName(string first, string second, bool preferSecond)
    {
        if (string.Equals(first, second, StringComparison.OrdinalIgnoreCase))
        {
            return first;
        }

        var firstScore = NameQualityScore(first);
        var secondScore = NameQualityScore(second);
        if (firstScore != secondScore)
        {
            return firstScore > secondScore ? first : second;
        }

        if (first.Length != second.Length)
        {
            return first.Length > second.Length ? first : second;
        }

        return preferSecond ? second : first;
    }

    private static int NameQualityScore(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return 0;
        }

        var normalized = name.Trim();
        if (normalized.Equals("Unknown", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals("Device", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals("Miscellaneous", StringComparison.OrdinalIgnoreCase))
        {
            return 1;
        }

        return 2;
    }
}

internal sealed class UsbVendorDatabaseCore(
    IReadOnlyDictionary<string, string> vendors,
    IReadOnlyDictionary<string, Dictionary<string, string>> products)
{
    public IReadOnlyDictionary<string, string> Vendors { get; } = vendors;
    public IReadOnlyDictionary<string, Dictionary<string, string>> Products { get; } = products;
}
