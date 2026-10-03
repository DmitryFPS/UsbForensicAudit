using System.ComponentModel;
using System.Runtime.InteropServices;

namespace UsbForensicAudit;

internal sealed record ClassicBluetoothDevice(string Address, string Name, uint ClassOfDevice, bool Connected);

/// <summary>Passive Classic Bluetooth state. PnP/container presence is not radio connectivity.</summary>
internal sealed record ClassicBluetoothSnapshot(IReadOnlyDictionary<string, ClassicBluetoothDevice> Devices, string Error = "")
{
    internal bool? Connection(string address) => Error.Length == 0 && Devices.TryGetValue(address, out var device)
        ? device.Connected : null;

    internal static ClassicBluetoothSnapshot Capture()
    {
        var devices = new Dictionary<string, ClassicBluetoothDevice>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var search = new Search { Size = (uint)Marshal.SizeOf<Search>(), Authenticated = 1, Remembered = 1, Unknown = 1, Connected = 1 };
            var info = NewInfo();
            var handle = BluetoothFindFirstDevice(ref search, ref info);
            if (handle == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                return new(devices, error == 259 ? "" : DescribeError(error));
            }
            try
            {
                do
                {
                    var address = info.Address.ToString("X12");
                    if (info.Address is > 0 and < 0xFFFFFFFFFFFF)
                    {
                        var connected = info.Connected != 0 || (devices.TryGetValue(address, out var previous) && previous.Connected);
                        devices[address] = new(address, info.Name, info.Class, connected);
                    }
                    info = NewInfo();
                } while (BluetoothFindNextDevice(handle, ref info));
                var error = Marshal.GetLastWin32Error();
                return new(devices, error == 259 ? "" : DescribeError(error));
            }
            finally { BluetoothFindDeviceClose(handle); }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or System.Security.SecurityException)
        { return new(devices, ex.Message); }
    }

    internal void Enrich(IEnumerable<UsbDeviceRecord> records)
    {
        if (Error.Length > 0) { return; }
        foreach (var record in records)
        {
            var address = BluetoothEnumeratorId.DeviceAddress(record.DeviceInstanceId);
            if (!Devices.TryGetValue(address, out var device)) { continue; }
            if (device.ClassOfDevice < 0x1000000) { record.BluetoothClassOfDevice ??= (int)device.ClassOfDevice; }
            if (string.IsNullOrWhiteSpace(record.FriendlyName) || record.FriendlyName.StartsWith("Bluetooth-устройство ", StringComparison.Ordinal))
            { record.FriendlyName = device.Name; }
        }
    }

    private static string DescribeError(int error) => $"Bluetooth API ({error}): {new Win32Exception(error).Message}";
    private static Info NewInfo() => new() { Size = (uint)Marshal.SizeOf<Info>(), Name = "" };

    [StructLayout(LayoutKind.Sequential)]
    private struct Search
    {
        public uint Size;
        public int Authenticated, Remembered, Unknown, Connected, IssueInquiry;
        public byte Timeout;
        public IntPtr Radio;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SystemTime { public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Info
    {
        public uint Size;
        public ulong Address;
        public uint Class;
        public int Connected, Remembered, Authenticated;
        public SystemTime LastSeen, LastUsed;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 248)] public string Name;
    }
    [DllImport("bthprops.cpl", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr BluetoothFindFirstDevice(ref Search search, ref Info info);
    [DllImport("bthprops.cpl", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool BluetoothFindNextDevice(IntPtr handle, ref Info info);
    [DllImport("bthprops.cpl", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool BluetoothFindDeviceClose(IntPtr handle);
}
