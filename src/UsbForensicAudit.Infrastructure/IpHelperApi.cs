using System.Runtime.InteropServices;

namespace UsbForensicAudit;

/// <summary>
/// Таблица соседей Windows: кто с каким IP и MAC виден с этой машины.
/// </summary>
internal static class IpHelperApi
{
    private const int Success = 0;
    private const int ErrorInsufficientBuffer = 122;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetIpNetTable(IntPtr table, ref int size, bool order);

    [DllImport("iphlpapi.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern int SendARP(
        uint destIp, uint srcIp, byte[] macAddr, ref int physicalAddrLen);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpNetRow
    {
        public int Index;
        public uint PhysAddrLen;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] PhysAddr;

        public uint Addr;
        public int Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpNetTable
    {
        public uint Count;

        // Первая строка; остальные идут подряд в памяти.
        public MibIpNetRow Row;
    }

    public sealed record ArpEntry(string IpAddress, string MacAddress, string State);

    public static IReadOnlyList<ArpEntry> ReadArpTable()
    {
        var size = 0;
        _ = GetIpNetTable(IntPtr.Zero, ref size, false);
        if (size <= 0)
        {
            return [];
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpNetTable(buffer, ref size, false) != Success)
            {
                return [];
            }

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibIpNetRow>();
            var offset = Marshal.SizeOf<uint>();
            var result = new List<ArpEntry>(count);
            for (var index = 0; index < count; index++)
            {
                var row = Marshal.PtrToStructure<MibIpNetRow>(buffer + offset + index * rowSize);
                if (row.PhysAddrLen == 0)
                {
                    continue;
                }

                var ip = new System.Net.IPAddress(BitConverter.GetBytes(row.Addr)).ToString();
                var mac = MacAddress.Format(row.PhysAddr.AsSpan(0, (int)Math.Min(row.PhysAddrLen, 6)));
                if (mac.Length == 0 || ip is "0.0.0.0" or "255.255.255.255")
                {
                    continue;
                }

                result.Add(new ArpEntry(ip, mac, DescribeType(row.Type)));
            }

            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static string? TryResolveMac(string ipAddress)
    {
        if (!System.Net.IPAddress.TryParse(ipAddress, out var parsed))
        {
            return null;
        }

        var bytes = parsed.GetAddressBytes();
        if (bytes.Length != 4)
        {
            return null;
        }

        var dest = BitConverter.ToUInt32(bytes, 0);
        var buffer = new byte[6];
        var length = buffer.Length;
        return SendARP(dest, 0, buffer, ref length) == 0 && length > 0
            ? MacAddress.Format(buffer.AsSpan(0, length))
            : null;
    }

    private static string DescribeType(int type) => type switch
    {
        4 => "постоянная",
        3 => "активна",
        2 => "устарела",
        1 => "недостижима",
        _ => "неизвестна"
    };
}
