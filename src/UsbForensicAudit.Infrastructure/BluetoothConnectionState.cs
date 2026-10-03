using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace UsbForensicAudit;

/// <summary>Сопряжённый Bluetooth остаётся в PnP даже без радиосоединения.</summary>
internal static class BluetoothConnectionState
{
    private static readonly Guid ContainerProperties = new("78c34fc8-104a-4aca-9ea4-524d52996e57");

    internal static bool IsRemoteInstance(string id) => BluetoothEnumeratorId.DeviceAddress(id).Length > 0
        || (id.StartsWith(@"BTHHFENUM\BthHFPAudio\", StringComparison.OrdinalIgnoreCase)
            && DeviceRemovalPolicy.IsInstanceId(id));

    internal static bool Resolve(string id, bool pnpPresent, Func<string, bool?> readConnection)
    {
        if (!pnpPresent || !IsRemoteInstance(id))
        {
            return pnpPresent;
        }
        return readConnection(id) ?? throw new InvalidOperationException(
            "Не удалось проверить радиосоединение Bluetooth. Наличие сопряжения в PnP не подтверждает подключение.");
    }

    internal static bool? Read(string instanceId)
    {
        return Read(instanceId, ClassicBluetoothSnapshot.Capture, ReadContainerForInstance);
    }

    internal static bool? Read(string instanceId, Func<ClassicBluetoothSnapshot> classic, Func<string, bool?> container)
    {
        if (instanceId.StartsWith(@"BTHENUM\", StringComparison.OrdinalIgnoreCase))
        {
            var address = BluetoothEnumeratorId.DeviceAddress(instanceId);
            // A remembered container can remain IsConnected after the phone turns its radio off.
            // Do not fall back to that stale value when Classic state is unavailable.
            return address.Length > 0 ? classic().Connection(address) : null;
        }
        return container(instanceId);
    }

    internal static bool? ReadContainerForInstance(string instanceId)
    {
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var instance = machine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + instanceId);
        var container = instance?.GetValue("ContainerID") as string ?? "";
        if (!DeviceRemovalPolicy.SameContainer(container, container))
        {
            return null;
        }
        return ReadContainer(Guid.Parse(container));
    }

    internal static bool? ReadContainer(Guid container)
    {
        // DEVPKEY_DeviceContainer_IsConnected, DevObjectTypeDeviceContainer.
        // Container metadata is retained for LE; Classic connection state uses Bluetooth API.
        var requested = new CompositeKey { Format = ContainerProperties, Id = 55 };
        var result = DevGetObjectProperties(2, container.ToString("B"), 0, 1, ref requested,
            out var count, out var properties);
        try
        {
            if (result < 0 || count != 1 || properties == IntPtr.Zero)
            {
                return null;
            }
            var property = Marshal.PtrToStructure<DeviceProperty>(properties);
            if (property.Key.Format != ContainerProperties || property.Key.Id != 55 || property.Key.Store != 0
                || property.Type != 0x11 || property.Size != 1 || property.Buffer == IntPtr.Zero)
            {
                return null;
            }
            return DecodeBoolean(Marshal.ReadByte(property.Buffer));
        }
        finally
        {
            if (properties != IntPtr.Zero)
            {
                DevFreeObjectProperties(count, properties);
            }
        }
    }

    internal static bool? DecodeBoolean(byte value) => value switch { 0 => false, 0xff => true, _ => null };

    [StructLayout(LayoutKind.Sequential)]
    private struct CompositeKey
    {
        public Guid Format;
        public uint Id;
        public uint Store;
        public IntPtr Locale;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DeviceProperty
    {
        public CompositeKey Key;
        public uint Type;
        public uint Size;
        public IntPtr Buffer;
    }

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int DevGetObjectProperties(int type, string id, uint flags, uint requestedCount,
        ref CompositeKey requested, out uint count, out IntPtr properties);

    [DllImport("cfgmgr32.dll", ExactSpelling = true)]
    private static extern void DevFreeObjectProperties(uint count, IntPtr properties);
}
