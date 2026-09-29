using System.Runtime.InteropServices;
using System.Text;

namespace UsbForensicAudit;

public sealed partial class WindowsDeviceRemovalPlatform
{
    private static string ReadParentDeviceId(string instanceId)
    {
        if (CM_Locate_DevNodeW(out var node, instanceId, 1) != 0) { return ""; }
        var property = new ParentPropertyKey { Format = new("4340a6c5-93fa-4706-972c-7b648008a5a7"), Id = 8 };
        var buffer = new byte[4096];
        var length = (uint)buffer.Length;
        if (CM_Get_DevNode_PropertyW(node, ref property, out var type, buffer, ref length, 0) != 0
            || type != 0x12 || length > buffer.Length || length % 2 != 0) { return ""; }
        var parent = Encoding.Unicode.GetString(buffer, 0, (int)length).TrimEnd('\0');
        // Windows возвращает HTREE, когда прежний родитель уже удалён.
        return parent.StartsWith(@"HTREE\", StringComparison.OrdinalIgnoreCase) ? "" : parent;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ParentPropertyKey { public Guid Format; public uint Id; }

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint CM_Get_DevNode_PropertyW(uint device, ref ParentPropertyKey key, out uint type, byte[] buffer, ref uint size, uint flags);
}
