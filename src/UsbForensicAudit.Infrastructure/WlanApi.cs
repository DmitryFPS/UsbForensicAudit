using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace UsbForensicAudit;

/// <summary>
/// Служба беспроводных сетей Windows: через неё видно, какие сети слышит
/// радиомодуль машины.
///
/// Вызовы идут напрямую в wlanapi.dll, а не через «netsh wlan show networks»:
/// вывод netsh переведён на язык системы и разбирать его пришлось бы по
/// русским словам, а на англоязычной Windows разбор молча ломался бы.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "P/Invoke wlanapi.dll — требует службы WLAN")]
internal static class WlanApi
{
    public const int Success = 0;
    public const uint ClientVersionVista = 2;

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern int WlanOpenHandle(
        uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr clientHandle);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern int WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern int WlanEnumInterfaces(
        IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern int WlanGetAvailableNetworkList(
        IntPtr clientHandle, ref Guid interfaceGuid, uint flags, IntPtr reserved, out IntPtr networkList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern int WlanGetNetworkBssList(
        IntPtr clientHandle,
        ref Guid interfaceGuid,
        IntPtr ssid,
        WlanBssType bssType,
        [MarshalAs(UnmanagedType.Bool)] bool securityEnabled,
        IntPtr reserved,
        out IntPtr bssList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern int WlanScan(
        IntPtr clientHandle, ref Guid interfaceGuid, IntPtr ssid, IntPtr ieData, IntPtr reserved);

    [DllImport("wlanapi.dll")]
    public static extern void WlanFreeMemory(IntPtr memory);

    public enum WlanBssType
    {
        Any = 3
    }

    public enum WlanInterfaceState
    {
        NotReady = 0,
        Connected = 1,
        AdHocNetworkFormed = 2,
        Disconnecting = 3,
        Disconnected = 4,
        Associating = 5,
        Discovering = 6,
        Authenticating = 7
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WlanInterfaceInfo
    {
        public Guid InterfaceGuid;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string InterfaceDescription;

        public WlanInterfaceState State;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Dot11Ssid
    {
        public uint SsidLength;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] Ssid;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WlanAvailableNetwork
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string ProfileName;

        public Dot11Ssid Ssid;
        public uint BssType;
        public uint NumberOfBssids;
        [MarshalAs(UnmanagedType.Bool)] public bool NetworkConnectable;
        public uint NotConnectableReason;
        public uint NumberOfPhyTypes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public uint[] PhyTypes;

        [MarshalAs(UnmanagedType.Bool)] public bool MorePhyTypes;
        public uint SignalQuality;
        [MarshalAs(UnmanagedType.Bool)] public bool SecurityEnabled;
        public Dot11AuthAlgorithm DefaultAuthAlgorithm;
        public Dot11CipherAlgorithm DefaultCipherAlgorithm;
        public uint Flags;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WlanBssEntry
    {
        public Dot11Ssid Ssid;
        public uint PhyId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Bssid;

        public uint BssType;
        public uint PhyType;
        public int Rssi;
        public uint LinkQuality;
        [MarshalAs(UnmanagedType.U1)] public bool InRegDomain;
        public ushort BeaconPeriod;
        public ulong Timestamp;
        public ulong HostTimestamp;
        public ushort CapabilityInformation;
        public uint ChCenterFrequency;
        public WlanRateSet RateSet;
        public uint IeOffset;
        public uint IeSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WlanRateSet
    {
        public uint RateSetLength;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)]
        public ushort[] Rates;
    }

    public enum Dot11AuthAlgorithm : uint
    {
        Open = 1,
        SharedKey = 2,
        Wpa = 3,
        WpaPsk = 4,
        WpaNone = 5,
        Rsna = 6,
        RsnaPsk = 7,
        Wpa3Enterprise192 = 8,
        Wpa3Sae = 9,
        Owe = 10,
        Wpa3Enterprise = 11
    }

    public enum Dot11CipherAlgorithm : uint
    {
        None = 0,
        Wep40 = 1,
        Tkip = 2,
        Ccmp = 4,
        Wep104 = 5,
        BipCmac128 = 6,
        Gcmp = 8,
        Gcmp256 = 9,
        Ccmp256 = 10,
        Wep = 0x101
    }

    /// <summary>Флаг из WlanGetAvailableNetworkList: сеть уже описана сохранённым профилем.</summary>
    public const uint NetworkConnected = 0x00000001;
    public const uint NetworkHasProfile = 0x00000002;

    /// <summary>Название способа защиты словами, как его понимает человек.</summary>
    public static string DescribeSecurity(
        bool securityEnabled, Dot11AuthAlgorithm auth, Dot11CipherAlgorithm cipher)
    {
        if (!securityEnabled && auth == Dot11AuthAlgorithm.Open)
        {
            return "Открытая сеть — данные передаются без шифрования";
        }

        var authText = auth switch
        {
            Dot11AuthAlgorithm.Open => "без проверки пароля",
            Dot11AuthAlgorithm.SharedKey => "общий ключ WEP",
            Dot11AuthAlgorithm.Wpa => "WPA (корпоративная)",
            Dot11AuthAlgorithm.WpaPsk => "WPA по паролю",
            Dot11AuthAlgorithm.WpaNone => "WPA без проверки",
            Dot11AuthAlgorithm.Rsna => "WPA2 (корпоративная)",
            Dot11AuthAlgorithm.RsnaPsk => "WPA2 по паролю",
            Dot11AuthAlgorithm.Wpa3Enterprise192 => "WPA3 (корпоративная, 192 бита)",
            Dot11AuthAlgorithm.Wpa3Sae => "WPA3 по паролю",
            Dot11AuthAlgorithm.Owe => "открытая сеть с шифрованием (OWE)",
            Dot11AuthAlgorithm.Wpa3Enterprise => "WPA3 (корпоративная)",
            _ => $"способ входа {(uint)auth}"
        };

        var cipherText = cipher switch
        {
            Dot11CipherAlgorithm.None => "без шифрования",
            Dot11CipherAlgorithm.Wep40 or Dot11CipherAlgorithm.Wep104 or Dot11CipherAlgorithm.Wep => "шифрование WEP (устарело)",
            Dot11CipherAlgorithm.Tkip => "шифрование TKIP (устарело)",
            Dot11CipherAlgorithm.Ccmp => "шифрование AES-CCMP",
            Dot11CipherAlgorithm.Ccmp256 => "шифрование AES-CCMP 256",
            Dot11CipherAlgorithm.Gcmp => "шифрование AES-GCMP",
            Dot11CipherAlgorithm.Gcmp256 => "шифрование AES-GCMP 256",
            Dot11CipherAlgorithm.BipCmac128 => "защита управляющих кадров BIP",
            _ => $"шифрование {(uint)cipher}"
        };

        return $"{authText}, {cipherText}";
    }

    /// <summary>
    /// Номер канала по частоте. Windows отдаёт частоту в килогерцах, а на
    /// коробке роутера и в настройках стоит номер канала.
    /// </summary>
    public static (int Channel, string Band) ReadChannel(uint centerFrequencyKhz)
    {
        var megahertz = (int)(centerFrequencyKhz / 1000);
        return megahertz switch
        {
            >= 2412 and <= 2472 => ((megahertz - 2412) / 5 + 1, "2,4 ГГц"),
            2484 => (14, "2,4 ГГц"),
            >= 5160 and <= 5885 => ((megahertz - 5000) / 5, "5 ГГц"),
            >= 5955 and <= 7115 => ((megahertz - 5950) / 5, "6 ГГц"),
            _ => (0, megahertz > 0 ? $"{megahertz} МГц" : "")
        };
    }

    /// <summary>
    /// Уровень сигнала в процентах по мощности в дБм. Windows отдаёт
    /// проценты только для сетей с профилем, а мощность — для всех.
    /// </summary>
    public static int SignalPercent(int rssiDbm) => rssiDbm switch
    {
        >= -50 => 100,
        <= -100 => 0,
        _ => 2 * (rssiDbm + 100)
    };
}
