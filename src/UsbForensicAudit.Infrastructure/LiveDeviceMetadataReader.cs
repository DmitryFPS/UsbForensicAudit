using Microsoft.Win32;

namespace UsbForensicAudit;

internal static class LiveDeviceMetadataReader
{
    public static (string Manufacturer, string Product, string Revision) Read(string pnpDeviceId)
    {
        if (string.IsNullOrWhiteSpace(pnpDeviceId))
        {
            return ("", "", "");
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + pnpDeviceId);
            if (key is not null)
            {
                return (
                    Clean(key.GetValue("Mfg")?.ToString()),
                    Clean(key.GetValue("DeviceDesc")?.ToString()),
                    "");
            }
        }
        catch
        {
            // Запасной вариант — разбор пути экземпляра устройства.
        }

        return ParseFromInstancePath(pnpDeviceId);
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
}
