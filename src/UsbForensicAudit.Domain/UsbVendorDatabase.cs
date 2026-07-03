using System.IO;
using System.Reflection;
using System.Text;

namespace UsbForensicAudit;

public sealed class UsbVendorLookup
{
    public string? Vid { get; init; }
    public string? Pid { get; init; }
    public string? VendorName { get; init; }
    public string? ProductName { get; init; }

    public bool HasVendor => !string.IsNullOrWhiteSpace(Vid) && !string.IsNullOrWhiteSpace(VendorName);
    public bool HasProduct => HasVendor && !string.IsNullOrWhiteSpace(Pid) && !string.IsNullOrWhiteSpace(ProductName);

    public string DeviceDescription
    {
        get
        {
            if (HasProduct)
            {
                return $"{VendorName} — {ProductName}";
            }

            if (HasVendor)
            {
                return VendorName!;
            }

            return "";
        }
    }
}

public static class UsbVendorDatabase
{
    private const string EmbeddedResourceName = "UsbForensicAudit.Assets.USBVendors.txt";

    private static readonly Lazy<UsbVendorDatabaseCore> Core = new(LoadCore);

    public static bool IsKnownVendor(string vid) =>
        Core.Value.Vendors.ContainsKey(NormalizeVid(vid));

    public static UsbVendorLookup Lookup(string? vid, string? pid = null)
    {
        vid = NormalizeVid(vid);
        pid = NormalizePid(pid);

        if (string.IsNullOrWhiteSpace(vid))
        {
            return new UsbVendorLookup();
        }

        Core.Value.Vendors.TryGetValue(vid, out var vendorName);
        string? productName = null;
        if (!string.IsNullOrWhiteSpace(pid)
            && Core.Value.Products.TryGetValue(vid, out var products))
        {
            products.TryGetValue(pid, out productName);
        }

        return new UsbVendorLookup
        {
            Vid = vid,
            Pid = string.IsNullOrWhiteSpace(pid) ? null : pid,
            VendorName = vendorName,
            ProductName = productName
        };
    }

    public static string? ResolveExternalOverridePath()
    {
        var fromEnv = Environment.GetEnvironmentVariable("USBFORENSIC_USBVENDORS_PATH");
        if (!string.IsNullOrWhiteSpace(fromEnv) && File.Exists(fromEnv))
        {
            return fromEnv;
        }

        var desktopPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            "USBVendors.txt");

        return File.Exists(desktopPath) ? desktopPath : null;
    }

    private static UsbVendorDatabaseCore LoadCore()
    {
        var overridePath = ResolveExternalOverridePath();
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            return UsbVendorDatabaseParser.ToCore(UsbVendorDatabaseParser.ParseFile(overridePath!));
        }

        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(EmbeddedResourceName);
        if (stream is not null)
        {
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return UsbVendorDatabaseParser.ToCore(UsbVendorDatabaseParser.Parse(reader));
        }

        return new UsbVendorDatabaseCore(
            new Dictionary<string, string>(),
            new Dictionary<string, Dictionary<string, string>>());
    }

    private static string NormalizeVid(string? vid) =>
        string.IsNullOrWhiteSpace(vid) ? "" : vid.Trim().ToUpperInvariant();

    private static string NormalizePid(string? pid) =>
        string.IsNullOrWhiteSpace(pid) ? "" : pid.Trim().ToUpperInvariant();
}
