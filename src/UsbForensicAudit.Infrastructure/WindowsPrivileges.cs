using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace UsbForensicAudit;

/// <summary>
/// Включение привилегий текущего процесса. Права администратора сами по себе не
/// дают читать ключи реестра и файлы, чей список доступа их не разрешает:
/// нужна привилегия SeBackupPrivilege, и она по умолчанию выключена даже у
/// администратора. Без неё сборщик молча пропускает ветки Enum и получает
/// неполную картину.
/// </summary>
public static class WindowsPrivileges
{
    public const string Backup = "SeBackupPrivilege";
    public const string Restore = "SeRestorePrivilege";
    public const string Security = "SeSecurityPrivilege";
    public const string TakeOwnership = "SeTakeOwnershipPrivilege";

    private const int TokenAdjustPrivileges = 0x0020;
    private const int TokenQuery = 0x0008;
    private const int SePrivilegeEnabled = 0x0002;
    private const int ErrorNotAllAssigned = 1300;

    public static bool TryEnable(string privilegeName, out string error)
    {
        error = "";
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
            {
                error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                return false;
            }

            try
            {
                if (!LookupPrivilegeValue(null, privilegeName, out var luid))
                {
                    error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                    return false;
                }

                var privileges = new TokenPrivileges
                {
                    PrivilegeCount = 1,
                    Luid = luid,
                    Attributes = SePrivilegeEnabled
                };

                if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                    return false;
                }

                // AdjustTokenPrivileges возвращает успех, даже если привилегия
                // процессу не назначена, поэтому результат проверяется отдельно.
                var lastError = Marshal.GetLastWin32Error();
                if (lastError == ErrorNotAllAssigned)
                {
                    error = $"Привилегия {privilegeName} не назначена процессу.";
                    return false;
                }

                return true;
            }
            finally
            {
                CloseHandle(token);
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public static bool IsLocalSystem()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User is not null
                   && identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid);
        }
        catch
        {
            return false;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public int PrivilegeCount;
        public Luid Luid;
        public int Attributes;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, int desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        ref TokenPrivileges newState,
        int bufferLength,
        IntPtr previousState,
        IntPtr returnLength);
}
