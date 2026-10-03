using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace UsbForensicAudit;

/// <summary>Queries the port of an exact USB devnode. Never infers a connector from VID/PID or USB speed.</summary>
internal static class UsbConnectorProbe
{
    private static readonly Guid HubInterface = new("f18a0e88-c30c-11d0-8815-00a0c906bed8");
    private static readonly Guid DeviceProperties = new("a45c254e-df1c-4efd-8020-67d146a850e0");
    private const uint GetDriverKey = (0x22u << 16) | (264u << 2);
    private const uint GetConnector = (0x22u << 16) | (278u << 2);

    internal static (string Type, string Provenance) Read(string id)
    {
        try
        {
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (var depth = 0; depth < 16 && id.Length > 0 && visited.Add(id); depth++)
            {
                var parent = WindowsPnpProperties.Parent(id);
                if (parent.Length == 0) { break; }
                var hubs = HubPaths(parent);
                if (hubs.Length > 0)
                {
                    var location = WindowsPnpProperties.TextProperty(id, DeviceProperties, 15);
                    var port = ParsePort(location);
                    var driver = WindowsPnpProperties.TextProperty(id, DeviceProperties, 11);
                    if (port == 0 || driver.Length == 0) { return ("Unknown", "Не удалось однозначно сопоставить устройство с портом USB-концентратора."); }
                    foreach (var hub in hubs)
                    {
                        using var handle = CreateFileW(hub, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
                        if (handle.IsInvalid) { continue; }
                        var key = Query(handle, GetDriverKey, port);
                        // Port numbers/location strings alone can be stale. Verify the actual attached driver key.
                        if (!DriverKeyMatches(key, driver)) { continue; }
                        var properties = Query(handle, GetConnector, port);
                        if (DecodeTypeC(properties, port) && DriverKeyMatches(Query(handle, GetDriverKey, port), driver))
                        {
                            return ("Type-C", $"IOCTL_USB_GET_PORT_CONNECTOR_PROPERTIES: hub={parent}; port={port}; device={id}; PortConnectorIsTypeC=1");
                        }
                        return ("Unknown", "Драйвер USB-порта не подтвердил Type-C; тип разъёма не устанавливается по отсутствию флага.");
                    }
                    return ("Unknown", "Свойства USB-порта недоступны или устройство изменилось во время опроса.");
                }
                if (parent.StartsWith(@"PCI\", StringComparison.OrdinalIgnoreCase)) { break; }
                id = parent;
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or System.Security.SecurityException or ArgumentException)
        { return ("Unknown", "Свойства USB-порта недоступны: " + ex.Message); }
        return ("Unknown", "USB-порт не установлен по текущей топологии.");
    }

    internal static uint ParsePort(string location)
    {
        var match = Regex.Match(location, @"^Port_#(?<port>\d+)\.Hub_#\d+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success && uint.TryParse(match.Groups["port"].Value, out var port) && port is > 0 and <= 255 ? port : 0;
    }

    internal static bool DriverKeyMatches(byte[] buffer, string expected) => buffer.Length >= 10
        && BitConverter.ToUInt32(buffer, 4) is var length && length >= 10 && length <= buffer.Length && length % 2 == 0
        && expected.Length > 0 && Encoding.Unicode.GetString(buffer, 8, (int)length - 8).TrimEnd('\0').Equals(expected, StringComparison.OrdinalIgnoreCase);

    internal static bool DecodeTypeC(byte[] buffer, uint port) => buffer.Length >= 18
        && BitConverter.ToUInt32(buffer, 0) == port && port is > 0 and <= 255
        && BitConverter.ToUInt32(buffer, 4) is var length && length >= 18 && length <= buffer.Length
        && (BitConverter.ToUInt32(buffer, 8) & 8u) != 0;

    private static byte[] Query(SafeFileHandle handle, uint ioctl, uint port)
    {
        var input = new byte[8192];
        BitConverter.GetBytes(port).CopyTo(input, 0);
        var output = new byte[input.Length];
        return DeviceIoControl(handle, ioctl, input, (uint)input.Length, output, (uint)output.Length, out var count, IntPtr.Zero)
               && count <= output.Length ? output[..(int)count] : [];
    }

    private static string[] HubPaths(string parent)
    {
        var guid = HubInterface;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            if (CM_Get_Device_Interface_List_SizeW(out var length, ref guid, parent, 0) != 0 || length > 65536) { return []; }
            var buffer = new char[Math.Max(length, 2)];
            var result = CM_Get_Device_Interface_ListW(ref guid, parent, buffer, (uint)buffer.Length, 0);
            if (result == 0x1A) { continue; }
            return result == 0 ? new string(buffer).Split('\0', StringSplitOptions.RemoveEmptyEntries) : [];
        }
        return [];
    }

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint CM_Get_Device_Interface_List_SizeW(out uint length, ref Guid guid, string id, uint flags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint CM_Get_Device_Interface_ListW(ref Guid guid, string id, [Out] char[] buffer, uint length, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, byte[] input, uint inputSize, [Out] byte[] output, uint outputSize, out uint returned, IntPtr overlapped);
}
