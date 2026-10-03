using System.Management;
using System.Runtime.InteropServices;
using System.Text;

namespace UsbForensicAudit;

/// <summary>Read-only, present-only enumeration. A failed probe is never an empty successful scan.</summary>
internal sealed record WindowsPnpSnapshot(IReadOnlyDictionary<string, bool?> States, bool Complete, string Error)
{
    internal ClassicBluetoothSnapshot? ClassicBluetooth { get; init; }
    internal static WindowsPnpSnapshot Capture()
    {
        var classic = new Lazy<ClassicBluetoothSnapshot>(ClassicBluetoothSnapshot.Capture);
        var snapshot = Capture(WindowsPnpProperties.PresentIds, WmiIds,
            id => BluetoothConnectionState.Read(id, () => classic.Value, BluetoothConnectionState.ReadContainerForInstance));
        return snapshot with { ClassicBluetooth = classic.IsValueCreated ? classic.Value : null };
    }

    internal static WindowsPnpSnapshot Capture(Func<string[]> nativeIds, Func<string[]> fallbackIds, Func<string, bool?> bluetooth)
    {
        string[] ids;
        var warning = "";
        try { ids = nativeIds(); }
        catch (Exception first)
        {
            try
            {
                ids = fallbackIds();
                warning = $"PnP API недоступен: {first.Message}. Использован WMI Present=TRUE.";
            }
            catch (Exception second)
            {
                return new(new Dictionary<string, bool?>(), false,
                    $"Текущие подключения не проверены. PnP: {first.Message}; WMI: {second.Message}");
            }
        }

        var states = new Dictionary<string, bool?>(StringComparer.OrdinalIgnoreCase);
        foreach (var id in ids.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            bool? connected = true;
            if (BluetoothConnectionState.IsRemoteInstance(id))
            {
                try { connected = bluetooth(id); }
                catch (Exception) { connected = null; }
            }
            states[id] = connected;
        }
        if (states.Values.Any(x => !x.HasValue))
        {
            warning += " Состояние радиосоединения части Bluetooth-устройств не удалось проверить; сопряжение не равно соединению.";
        }
        return new(states, true, warning.Trim());
    }

    private static string[] WmiIds()
    {
        using var searcher = new ManagementObjectSearcher("SELECT PNPDeviceID FROM Win32_PnPEntity WHERE Present = TRUE");
        using var items = searcher.Get();
        var ids = new List<string>();
        foreach (ManagementObject item in items)
        {
            using (item)
            {
                if (item["PNPDeviceID"] is string id && id.Length > 0) { ids.Add(id); }
            }
        }
        return ids.ToArray();
    }

    internal ConnectedDeviceIndex ToIndex() => ConnectedDeviceIndex.FromSnapshot(
        States.Where(x => x.Value == true).Select(x => x.Key),
        States.Where(x => !x.Value.HasValue).Select(x => x.Key), Complete, Error);
}

internal static class WindowsPnpProperties
{
    private const uint Present = 0x100;
    private const uint BufferSmall = 0x1A;
    internal static string[] PresentIds()
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var result = CM_Get_Device_ID_List_SizeW(out var length, null, Present);
            if (result != 0 || length > 16_000_000) { throw new InvalidOperationException($"CM_Get_Device_ID_List_Size: 0x{result:X}"); }
            var buffer = new char[Math.Max(length, 2)];
            result = CM_Get_Device_ID_ListW(null, buffer, (uint)buffer.Length, Present);
            if (result == BufferSmall) { continue; }
            if (result != 0) { throw new InvalidOperationException($"CM_Get_Device_ID_List: 0x{result:X}"); }
            return new string(buffer).Split('\0', StringSplitOptions.RemoveEmptyEntries);
        }
        throw new InvalidOperationException("Список PnP изменялся во время чтения; нужен повторный опрос.");
    }

    internal static string Parent(string id) => TextProperty(id, new("4340a6c5-93fa-4706-972c-7b648008a5a7"), 8);

    internal static string TextProperty(string id, Guid format, uint pid)
    {
        var data = Property(id, format, pid, out var type);
        return type == 0x12 && data.Length % 2 == 0 ? Encoding.Unicode.GetString(data).TrimEnd('\0') : "";
    }

    internal static byte[] Property(string id, Guid format, uint pid, out uint type)
    {
        type = 0;
        try
        {
            if (CM_Locate_DevNodeW(out var node, id, 1) != 0) { return []; }
            var key = new PropertyKey { Format = format, Id = pid };
            var buffer = new byte[8192];
            var length = (uint)buffer.Length;
            if (CM_Get_DevNode_PropertyW(node, ref key, out type, buffer, ref length, 0) != 0 || length > buffer.Length)
            { type = 0; return []; }
            return buffer[..(int)length];
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or System.Security.SecurityException)
        { type = 0; return []; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PropertyKey { public Guid Format; public uint Id; }
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint CM_Get_Device_ID_List_SizeW(out uint length, string? filter, uint flags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint CM_Get_Device_ID_ListW(string? filter, [Out] char[] buffer, uint length, uint flags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint CM_Locate_DevNodeW(out uint node, string id, uint flags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint CM_Get_DevNode_PropertyW(uint node, ref PropertyKey key, out uint type, [Out] byte[] data, ref uint length, uint flags);
}
