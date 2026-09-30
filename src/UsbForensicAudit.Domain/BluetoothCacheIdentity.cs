using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public static class BluetoothCacheIdentity
{
    public static string AddressFromPath(string path)
    {
        var match = Regex.Match(path,
            @"^(?:HKLM|HKEY_LOCAL_MACHINE)\\SYSTEM\\(?:CurrentControlSet|ControlSet[0-9]{3})\\Services\\BTHPORT\\Parameters\\Devices\\(?<address>[0-9A-F]{12})$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        var address = match.Groups["address"].Value.ToUpperInvariant();
        return address is "000000000000" or "FFFFFFFFFFFF" ? "" : address;
    }
}
