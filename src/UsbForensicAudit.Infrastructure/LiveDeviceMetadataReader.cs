using Microsoft.Win32;

namespace UsbForensicAudit;

internal static class LiveDeviceMetadataReader
{
    public static (
        string Manufacturer,
        string Product,
        string Revision,
        string Service,
        string HardwareIds,
        string CompatibleIds,
        string LocationInformation,
        string LocationPaths) Read(string pnpDeviceId)
    {
        if (string.IsNullOrWhiteSpace(pnpDeviceId))
        {
            return ("", "", "", "", "", "", "", "");
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + pnpDeviceId);
            if (key is not null)
            {
                return (
                    Clean(key.GetValue("Mfg")?.ToString()),
                    Clean(key.GetValue("DeviceDesc")?.ToString()),
                    "",
                    Clean(key.GetValue("Service")?.ToString()),
                    ReadMultiString(key, "HardwareID"),
                    ReadMultiString(key, "CompatibleIDs"),
                    Clean(key.GetValue("LocationInformation")?.ToString()),
                    ReadMultiString(key, "LocationPaths"));
            }
        }
        catch
        {
            // Запасной вариант — разбор пути экземпляра устройства.
        }

        var parsed = ParseFromInstancePath(pnpDeviceId);
        return (parsed.Manufacturer, parsed.Product, parsed.Revision, "", "", "", "", "");
    }

    private static (string Manufacturer, string Product, string Revision) ParseFromInstancePath(string pnpDeviceId)
    {
        var manufacturer = "";
        var product = "";
        var revision = "";

        foreach (var part in pnpDeviceId.Split('\\', '&'))
        {
            if (part.StartsWith("Ven_", StringComparison.OrdinalIgnoreCase))
            {
                manufacturer = part[4..];
            }
            else if (part.StartsWith("Prod_", StringComparison.OrdinalIgnoreCase))
            {
                product = part[5..];
            }
            else if (part.StartsWith("Rev_", StringComparison.OrdinalIgnoreCase))
            {
                revision = part[4..];
            }
        }

        return (Clean(manufacturer), Clean(product), Clean(revision));
    }

    private static string Clean(string? value)
    {
        return TextSanitizer.Clean(value ?? "", 180);
    }

    private static string ReadMultiString(RegistryKey key, string name)
    {
        return key.GetValue(name) switch
        {
            string[] values => string.Join("; ", values.Select(Clean)),
            string value => Clean(value),
            _ => ""
        };
    }
}
