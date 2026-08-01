using System.Net;
using System.Net.Sockets;

namespace UsbForensicAudit;

/// <summary>
/// Отделяет настоящие устройства сети от служебного шума таблицы соседей.
///
/// Windows складывает в таблицу соседей не только устройства: туда попадают
/// групповые (multicast) адреса рассылок, широковещательный адрес и авто-адреса
/// link-local. Это не устройства — показывать их в списке «кто в сети» значит
/// хоронить настоящие находки под десятками бессмысленных строк.
/// </summary>
public static class NetworkAddressFilter
{
    /// <summary>
    /// Адрес — служебный шум, а не устройство: групповая рассылка
    /// (224.0.0.0–239.255.255.255 и выше), широковещательный адрес,
    /// link-local (169.254.0.0/16) или петля на саму машину (127.0.0.0/8).
    /// </summary>
    public static bool IsNoise(string? ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress)
            || !IPAddress.TryParse(ipAddress, out var parsed))
        {
            return true;
        }

        if (parsed.AddressFamily != AddressFamily.InterNetwork)
        {
            // IPv6: групповые адреса ff00::/8 и link-local fe80::/10 — тот же шум.
            if (parsed.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return parsed.IsIPv6Multicast || parsed.IsIPv6LinkLocal || IPAddress.IsLoopback(parsed);
            }

            return true;
        }

        var bytes = parsed.GetAddressBytes();
        return bytes[0] >= 224 // multicast 224–239 и зарезервированные 240+
               || bytes[0] == 127
               || (bytes[0] == 169 && bytes[1] == 254)
               || (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255)
               || bytes.All(x => x == 0);
    }

    /// <summary>
    /// Адаптер — виртуальный или туннельный: VPN, TAP, гипервизор. Соседи за
    /// таким адаптером — не локальная сеть, и опрашивать его подсеть смысла нет.
    /// </summary>
    public static bool IsVirtualAdapterDescription(string? description)
    {
        if (string.IsNullOrWhiteSpace(description))
        {
            return false;
        }

        ReadOnlySpan<string> markers =
        [
            "vpn", "tap-", "tap adapter", "tun", "wireguard", "openvpn",
            "hyper-v", "vmware", "virtualbox", "virtual adapter",
            "virtual ethernet", "loopback", "teredo", "isatap", "tailscale", "zerotier"
        ];
        foreach (var marker in markers)
        {
            if (description.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
