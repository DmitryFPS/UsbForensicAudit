using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public static class CleanerToolCatalog
{
    private static readonly Regex PrefetchHashSuffixRegex = new(
        @"-[0-9A-F]{8}\.pf$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex VersionSuffixRegex = new(
        @"_v\d+(?:\.\d+)*$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static readonly string[] ToolPatterns =
    [
        "usbdeview",
        "usbdetector",
        "usbtracecleaner",
        "usb trace cleaner",
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
        "wmic",
        "sdelete",
        "r-wipe",
        "rwipe",
        "wise disk cleaner",
        "wisecare365",
        "tracks eraser",
        "eraser.exe",
        "fsutil",
        "reg.exe"
    ];

    public static readonly string[] TrackedUtilityPatterns =
    [
        "usbdeview",
        "usbdetector",
        "usbtracecleaner",
        "usb trace cleaner",
        "usb oblivion",
        "usboblivion",
        "privacy eraser",
        "ccleaner",
        "bleachbit",
        "privazer",
        "device cleanup",
        "devicecleanup",
        "sdelete",
        "r-wipe",
        "r-wipe & clean",
        "rwipe",
        "wise disk cleaner",
        "wisecare365",
        "wise care 365",
        "tracks eraser",
        "eraser.exe",
        "eraser"
    ];

    private static readonly string[] TraceRemovalPatterns =
    [
        "usbtracecleaner",
        "usb trace cleaner",
        "usb oblivion",
        "usboblivion",
        "privacy eraser",
        "ccleaner",
        "bleachbit",
        "privazer",
        "device cleanup",
        "devicecleanup",
        "sdelete",
        "r-wipe",
        "r-wipe & clean",
        "rwipe",
        "wise disk cleaner",
        "wisecare365",
        "wise care 365",
        "tracks eraser",
        "eraser.exe",
        "eraser"
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
            "usbtracecleaner" => "USB Trace Cleaner",
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
            "sdelete" => "SDelete",
            "r-wipe" or "r-wipe & clean" or "rwipe" => "R-Wipe & Clean",
            "wise disk cleaner" => "Wise Disk Cleaner",
            "wisecare365" or "wise care 365" => "Wise Care 365",
            "tracks eraser" => "Tracks Eraser",
            "eraser.exe" or "eraser" => "Eraser",
            "fsutil" => "FSUtil",
            "reg.exe" => "Registry Console (reg.exe)",
            _ => pattern
        };
    }

    public static bool LooksLikeCleaner(string? value)
    {
        return Match(value) is not null;
    }

    public static string? MatchTrackedUtility(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var direct = TrackedUtilityPatterns.FirstOrDefault(pattern =>
            text.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        if (direct is not null)
        {
            return direct;
        }

        var normalized = NormalizeExecutableToken(text);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return null;
        }

        return TrackedUtilityPatterns.FirstOrDefault(pattern =>
            normalized.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    public static string NormalizeExecutableToken(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "";
        }

        var token = text.Trim();
        token = PrefetchHashSuffixRegex.Replace(token, "");
        var dashIndex = token.LastIndexOf('-');
        if (dashIndex > 0 && token.EndsWith(".pf", StringComparison.OrdinalIgnoreCase) == false
            && dashIndex == token.Length - 9)
        {
            token = token[..dashIndex];
        }

        if (token.EndsWith(".pf", StringComparison.OrdinalIgnoreCase))
        {
            token = token[..^3];
        }

        if (token.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            token = token[..^4];
        }

        token = VersionSuffixRegex.Replace(token, "");
        return token.Replace('_', ' ').Replace('-', ' ').Trim().ToLowerInvariant();
    }

    public static bool LooksLikeTrackedUtility(string? value) =>
        MatchTrackedUtility(value) is not null;

    public static bool IsTraceRemovalTool(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = NormalizeExecutableToken(value).Replace(" ", "", StringComparison.Ordinal);
        return TraceRemovalPatterns.Any(pattern =>
            value.Contains(pattern, StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(pattern.Replace(" ", "", StringComparison.Ordinal), StringComparison.OrdinalIgnoreCase));
    }

    public static string? MatchExplicitCleanupCommand(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var normalized = $" {text.ToLowerInvariant().Replace('\r', ' ').Replace('\n', ' ')} ";
        if (normalized.Contains("wevtutil", StringComparison.Ordinal)
            && (normalized.Contains(" cl ", StringComparison.Ordinal)
                || normalized.Contains(" clear-log", StringComparison.Ordinal)))
        {
            return "wevtutil";
        }

        if ((normalized.Contains("powershell", StringComparison.Ordinal)
             || normalized.Contains("pwsh", StringComparison.Ordinal))
            && normalized.Contains("clear-eventlog", StringComparison.Ordinal))
        {
            return normalized.Contains("pwsh", StringComparison.Ordinal) ? "pwsh" : "powershell";
        }

        var hasUsbTraceTarget = ContainsAny(
            normalized,
            "usbstor",
            @"enum\usb",
            "mounteddevices",
            "setupapi.dev.log",
            "windows\\prefetch",
            "amcache.hve");
        if (hasUsbTraceTarget
            && (normalized.Contains("remove-item", StringComparison.Ordinal)
                || normalized.Contains("reg delete", StringComparison.Ordinal)
                || normalized.Contains("del ", StringComparison.Ordinal)))
        {
            if (normalized.Contains("powershell", StringComparison.Ordinal)
                || normalized.Contains("pwsh", StringComparison.Ordinal))
            {
                return normalized.Contains("pwsh", StringComparison.Ordinal) ? "pwsh" : "powershell";
            }

            return normalized.Contains("reg delete", StringComparison.Ordinal) ? "reg.exe" : "cmd.exe";
        }

        if (normalized.Contains("fsutil", StringComparison.Ordinal)
            && normalized.Contains("usn", StringComparison.Ordinal)
            && normalized.Contains("deletejournal", StringComparison.Ordinal))
        {
            return "fsutil";
        }

        return null;
    }

    public static readonly string[] UsbForensicToolPatterns =
    [
        "usbdeview",
        "usbdetector",
        "usbtracecleaner",
        "usb trace cleaner",
        "usb oblivion",
        "usboblivion"
    ];

    public static bool IsUsbForensicUtility(string? toolDisplayName)
    {
        if (string.IsNullOrWhiteSpace(toolDisplayName))
        {
            return false;
        }

        var normalized = NormalizeExecutableToken(toolDisplayName).Replace(" ", "", StringComparison.Ordinal);
        return UsbForensicToolPatterns.Any(pattern =>
            toolDisplayName.Contains(pattern, StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(pattern.Replace(" ", "", StringComparison.Ordinal), StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsOblivionTool(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        return text.Contains("usboblivion", StringComparison.OrdinalIgnoreCase)
               || text.Contains("usb oblivion", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsAny(string value, params string[] markers) =>
        markers.Any(marker => value.Contains(marker, StringComparison.Ordinal));
}
