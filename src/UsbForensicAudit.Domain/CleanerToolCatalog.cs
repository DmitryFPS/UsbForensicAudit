namespace UsbForensicAudit;

public static class CleanerToolCatalog
{
    public static readonly string[] ToolPatterns =
    [
        "usbdeview",
        "usbdetector",
        "usb oblivion",
        "usboblivion",
        "privacy eraser",
        "ccleaner",
        "bleachbit",
        "privazer",
        "device cleanup",
        "devicecleanup",
        "wevtutil",
        "powershell",
        "pwsh",
        "cmd.exe",
        "cleanmgr",
        "dism.exe",
        "wmic"
    ];

    public static string? Match(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        return ToolPatterns.FirstOrDefault(x => text.Contains(x, StringComparison.OrdinalIgnoreCase));
    }

    public static string DisplayName(string pattern)
    {
        return pattern.ToLowerInvariant() switch
        {
            "usbdeview" => "USBDeview",
            "usbdetector" => "USBDetector",
            "usb oblivion" or "usboblivion" => "USB Oblivion",
            "privacy eraser" => "Privacy Eraser",
            "ccleaner" => "CCleaner",
            "bleachbit" => "BleachBit",
            "privazer" => "PrivaZer",
            "device cleanup" or "devicecleanup" => "Device Cleanup",
            "wevtutil" => "wevtutil (очистка журналов)",
            "powershell" or "pwsh" => "PowerShell",
            "cmd.exe" => "Командная строка (cmd)",
            "cleanmgr" => "Очистка диска Windows",
            "dism.exe" => "DISM",
            "wmic" => "WMIC",
            _ => pattern
        };
    }

    public static bool LooksLikeCleaner(string? value)
    {
        return Match(value) is not null;
    }

    public static readonly string[] UsbForensicToolPatterns =
    [
        "usbdeview",
        "usbdetector",
        "usb oblivion",
        "usboblivion"
    ];

    public static bool IsUsbForensicUtility(string? toolDisplayName)
    {
        if (string.IsNullOrWhiteSpace(toolDisplayName))
        {
            return false;
        }

        return UsbForensicToolPatterns.Any(pattern =>
            toolDisplayName.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsOblivionTool(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        return text.Contains("oblivion", StringComparison.OrdinalIgnoreCase)
               || text.Contains("usb oblivion", StringComparison.OrdinalIgnoreCase);
    }
}
