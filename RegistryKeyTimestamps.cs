using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace UsbForensicAudit;

internal static class RegistryKeyTimestamps
{
    public static DateTimeOffset? GetLastWriteUtc(RegistryKey key)
    {
        try
        {
            var fileTime = GetLastWriteFileTime(key.Handle.DangerousGetHandle());
            if (fileTime <= 0)
            {
                return null;
            }

            var timestamp = DateTimeOffset.FromFileTime(fileTime);
            return DateDisplay.IsReliable(timestamp) ? timestamp : null;
        }
        catch
        {
            return null;
        }
    }

    private static long GetLastWriteFileTime(nint keyHandle)
    {
        const int errorSuccess = 0;
        var result = RegQueryInfoKey(
            keyHandle,
            null,
            null,
            nint.Zero,
            out _,
            out _,
            out _,
            out _,
            out _,
            out _,
            out _,
            out var lastWriteFileTime);

        return result == errorSuccess ? lastWriteFileTime : 0;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegQueryInfoKeyW")]
    private static extern int RegQueryInfoKey(
        nint hKey,
        string? lpClass,
        int[]? lpcchClass,
        nint lpReserved,
        out int lpcSubKeys,
        out int lpcbMaxSubKeyLen,
        out int lpcbMaxClassLen,
        out int lpcValues,
        out int lpcbMaxValueNameLen,
        out int lpcbMaxValueLen,
        out int lpcbSecurityDescriptor,
        out long lpftLastWriteTime);
}
