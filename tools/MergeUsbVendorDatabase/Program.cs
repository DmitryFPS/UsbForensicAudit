using System.Text;
using UsbForensicAudit;

var repoRoot = LocateRepoRoot();
var assetsPath = args.Length > 0 ? args[0] : Path.Combine(repoRoot, "Assets", "USBVendors.txt");
var downloadPath = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "tools", "usb.ids.download");

if (!File.Exists(assetsPath))
{
    Console.Error.WriteLine($"Base file not found: {assetsPath}");
    return 1;
}

if (!File.Exists(downloadPath))
{
    Console.Error.WriteLine($"Downloaded usb.ids not found: {downloadPath}");
    Console.Error.WriteLine("Download from http://www.linux-usb.org/usb.ids first.");
    return 1;
}

var existing = UsbVendorDatabaseParser.ParseFile(assetsPath);
var upstream = UsbVendorDatabaseParser.ParseFile(downloadPath);

var existingVendorCount = existing.Vendors.Count;
var existingProductCount = existing.Products.Values.Sum(x => x.Count);

var merged = new UsbVendorDatabaseData();
UsbVendorDatabaseParser.Merge(merged, existing, sourceWinsOnConflict: false);
UsbVendorDatabaseParser.Merge(merged, upstream, sourceWinsOnConflict: true);

var mergedProductCount = merged.Products.Values.Sum(x => x.Count);
Directory.CreateDirectory(Path.GetDirectoryName(assetsPath)!);
await using (var writer = new StreamWriter(assetsPath, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
{
    UsbVendorDatabaseParser.Write(writer, merged);
}

Console.WriteLine($"Merged database written to: {assetsPath}");
Console.WriteLine($"Vendors: {existingVendorCount} base + {upstream.Vendors.Count} upstream -> {merged.Vendors.Count}");
Console.WriteLine($"Products: {existingProductCount} base + {upstream.Products.Values.Sum(x => x.Count)} upstream -> {mergedProductCount}");
Console.WriteLine($"File size: {new FileInfo(assetsPath).Length:N0} bytes");
return 0;

static string LocateRepoRoot()
{
    var current = new DirectoryInfo(AppContext.BaseDirectory);
    for (var depth = 0; depth < 10 && current is not null; depth++)
    {
        if (File.Exists(Path.Combine(current.FullName, "UsbForensicAudit.csproj")))
        {
            return current.FullName;
        }

        current = current.Parent;
    }

    throw new InvalidOperationException("Could not locate UsbForensicAudit repository root.");
}
