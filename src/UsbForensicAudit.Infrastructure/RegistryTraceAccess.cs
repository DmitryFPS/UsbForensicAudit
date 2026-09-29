using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace UsbForensicAudit;

/// <summary>Existing-only registry access. Privileges apply to an isolated token, never to registry ACLs.</summary>
internal static class RegistryTraceAccess
{
    private const int KeyRead = 0x20019;
    private const int KeyDelete = 0x10000;
    private const int OpenLink = 8;
    private const int BackupRestore = 4;
    private const int MaxEntries = 4096;
    private const int MaxBytes = 32 * 1024 * 1024;

    internal static string? ReadFingerprint(string path)
    {
        var normalized = ValidatePath(path, allowActiveEnum: false);
        using var machine = OpenMachine();
        return ReadFingerprint(machine, ResolveCurrentControlSet(machine, normalized[19..]), normalized);
    }

    internal static void DeleteTree(string path, string expectedFingerprint)
    {
        var normalized = ValidatePath(path, allowActiveEnum: false);
        using var machine = OpenMachine();
        DeleteTree(machine, ResolveCurrentControlSet(machine, normalized[19..]), normalized, expectedFingerprint);
    }

    internal static void SaveKey(string path, string filePath)
    {
        var normalized = ValidatePath(path, allowActiveEnum: true);
        if (File.Exists(filePath))
        {
            throw new IOException("Файл резервной копии уже существует.");
        }
        WithPrivileges(write: false, requireBackup: true, privileged =>
        {
            using var machine = OpenMachine();
            using var key = OpenPath(machine, ResolveCurrentControlSet(machine, normalized[19..]), privileged, write: false)
                ?? throw new IOException("Запись исчезла перед резервным копированием.");
            var remaining = MaxEntries;
            var bytes = MaxBytes;
            // Validate every descendant, including symbolic links, before handing the tree to RegSaveKeyEx.
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            AppendKey(key, normalized, hash, privileged, 0, ref remaining, ref bytes);
            var error = RegSaveKeyEx(key.Handle, filePath, IntPtr.Zero, 2);
            if (error != 0)
            {
                ThrowError(error);
            }

            return true;
        });
    }

    internal static string ValidatePath(string path, bool allowActiveEnum)
    {
        if (DeviceTracePolicy.MountedValueName(path).Length > 0)
        {
            throw new ArgumentException("Значение MountedDevices нельзя обрабатывать как раздел реестра.", nameof(path));
        }
        var normalized = DeviceTracePolicy.NormalizePath(path);
        if (normalized is not null)
        {
            return normalized;
        }

        var expanded = path.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase)
            ? @"HKEY_LOCAL_MACHINE\" + path[5..] : path;
        const string prefix = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\";
        if (allowActiveEnum && expanded.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            && DeviceRemovalPolicy.IsInstanceId(expanded[prefix.Length..]))
        {
            return expanded;
        }

        throw new ArgumentException("Неподдерживаемая запись реестра.", nameof(path));
    }

    // The root overloads also exercise native traversal against isolated test keys, never device keys.
    internal static string? ReadFingerprint(RegistryKey root, string subPath, string identity)
        => WithPrivileges(write: false, requireBackup: false, privileged =>
        {
            using var key = OpenPath(root, subPath, privileged, write: false);
            if (key is null)
            {
                return null;
            }

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var remaining = MaxEntries;
            var bytes = MaxBytes;
            AppendKey(key, identity, hash, privileged, 0, ref remaining, ref bytes);
            return Convert.ToHexString(hash.GetHashAndReset());
        });

    internal static void DeleteTree(RegistryKey root, string subPath, string identity, string expectedFingerprint)
        => WithPrivileges(write: true, requireBackup: false, privileged =>
        {
            using var key = OpenPath(root, subPath, privileged, write: true);
            if (key is null)
            {
                return true;
            }
            // Revalidate the very handle that will be deleted, not a newly reopened path.
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var remaining = MaxEntries;
            var bytes = MaxBytes;
            AppendKey(key, identity, hash, privileged, 0, ref remaining, ref bytes);
            if (!string.Equals(expectedFingerprint, Convert.ToHexString(hash.GetHashAndReset()), StringComparison.Ordinal))
            {
                throw new IOException("Запись реестра изменилась. Удаление отменено.");
            }

            var descendants = new List<RegistryKey>();
            try
            {
                remaining = MaxEntries;
                CollectForDeletion(key, descendants, privileged, 0, ref remaining);
                // Handles are acquired for every child first; failure to open a protected child changes nothing.
                for (var i = descendants.Count - 1; i >= 0; i--)
                {
                    DeleteHandle(descendants[i]);
                }

                DeleteHandle(key);
            }
            finally
            {
                foreach (var child in descendants)
                {
                    child.Dispose();
                }
            }
            return true;
        });

    private static void CollectForDeletion(RegistryKey key, List<RegistryKey> keys, bool privileged, int depth, ref int remaining)
    {
        CheckLimit(depth, ref remaining);
        foreach (var name in key.GetSubKeyNames().Order(StringComparer.OrdinalIgnoreCase))
        {
            var child = OpenChild(key, name, privileged, write: true)
                ?? throw new IOException("Состав записи изменился при подготовке удаления.");
            keys.Add(child);
            RejectSymbolicLink(child);
            CollectForDeletion(child, keys, privileged, depth + 1, ref remaining);
        }
    }

    private static void DeleteHandle(RegistryKey key)
    {
        var status = NtDeleteKey(key.Handle);
        if (status < 0)
        {
            ThrowError(unchecked((int)RtlNtStatusToDosError(status)));
        }
    }

    private static void AppendKey(RegistryKey key, string identity, IncrementalHash hash, bool privileged,
        int depth, ref int remaining, ref int remainingBytes)
    {
        CheckLimit(depth, ref remaining);
        RejectSymbolicLink(key);
        AppendBytes(hash, Encoding.UTF8.GetBytes(identity.ToUpperInvariant()));
        foreach (var name in key.GetValueNames().Order(StringComparer.OrdinalIgnoreCase))
        {
            CheckLimit(depth, ref remaining);
            var (kind, value) = ReadValue(key, name);
            remainingBytes -= value.Length;
            if (remainingBytes < 0)
            {
                throw new IOException("Запись слишком велика для выборочного удаления.");
            }

            AppendBytes(hash, Encoding.UTF8.GetBytes(name.ToUpperInvariant()));
            AppendBytes(hash, BitConverter.GetBytes(kind));
            AppendBytes(hash, value);
        }
        foreach (var name in key.GetSubKeyNames().Order(StringComparer.OrdinalIgnoreCase))
        {
            using var child = OpenChild(key, name, privileged, write: false)
                ?? throw new IOException("Состав записи изменился при чтении.");
            AppendKey(child, identity + "\\" + name, hash, privileged, depth + 1, ref remaining, ref remainingBytes);
        }
    }

    private static void AppendBytes(IncrementalHash hash, byte[] bytes)
    {
        hash.AppendData(BitConverter.GetBytes(bytes.Length));
        hash.AppendData(bytes);
    }

    private static (uint Kind, byte[] Value) ReadValue(RegistryKey key, string name)
    {
        uint size = 0;
        var error = RegQueryValueEx(key.Handle, name, IntPtr.Zero, out var kind, null, ref size);
        if (error != 0)
        {
            ThrowError(error);
        }

        if (size > MaxBytes)
        {
            throw new IOException("Значение реестра слишком велико для выборочного удаления.");
        }

        var data = new byte[size];
        error = RegQueryValueEx(key.Handle, name, IntPtr.Zero, out kind, data, ref size);
        if (error != 0)
        {
            ThrowError(error);
        }

        if (size != data.Length)
        {
            Array.Resize(ref data, (int)size);
        }

        return (kind, data);
    }

    private static void RejectSymbolicLink(RegistryKey key)
    {
        if (key.GetValueNames().Contains("SymbolicLinkValue", StringComparer.OrdinalIgnoreCase)
            && ReadValue(key, "SymbolicLinkValue").Kind == 6)
        {
            throw new IOException("Символьные ссылки реестра не поддерживаются при выборочном удалении.");
        }
    }

    private static void CheckLimit(int depth, ref int remaining)
    {
        if (depth > 16 || --remaining < 0)
        {
            throw new IOException("Запись слишком велика для выборочного удаления.");
        }
    }

    private static string ResolveCurrentControlSet(RegistryKey machine, string path)
    {
        const string prefix = @"SYSTEM\CurrentControlSet\";
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return path;
        }

        using var select = machine.OpenSubKey(@"SYSTEM\Select");
        if (select?.GetValue("Current") is not int current || current is < 1 or > 999)
        {
            throw new IOException("Не удалось определить активный набор настроек Windows.");
        }

        return $@"SYSTEM\ControlSet{current:D3}\" + path[prefix.Length..];
    }

    private static RegistryKey? OpenPath(RegistryKey root, string subPath, bool privileged, bool write)
    {
        var parts = subPath.Split('\\');
        if (parts.Any(p => p.Length == 0 || p is "." or ".." || p.Any(char.IsControl)))
        {
            throw new ArgumentException("Недопустимый путь записи.", nameof(subPath));
        }

        RegistryKey? current = null;
        try
        {
            for (var i = 0; i < parts.Length; i++)
            {
                var next = OpenChild(current ?? root, parts[i], privileged, write && i == parts.Length - 1);
                current?.Dispose();
                current = next;
                if (current is null)
                {
                    return null;
                }

                RejectSymbolicLink(current);
            }
            var result = current;
            current = null;
            return result;
        }
        finally { current?.Dispose(); }
    }

    private static RegistryKey OpenMachine()
    {
        // RegistryKey.Handle у предопределённого HKLM запрашивает лишние права.
        // Открываем обычный дескриптор только для чтения; права конечного ключа
        // отдельно проверяет NtOpenKeyEx в контексте временного токена.
        var error = RegOpenKeyEx(new IntPtr(unchecked((int)0x80000002)), "", 0, KeyRead | 0x100, out var handle);
        if (error != 0)
        {
            handle?.Dispose();
            ThrowError(error);
        }
        return RegistryKey.FromHandle(handle!, RegistryView.Registry64);
    }

    private static RegistryKey? OpenChild(RegistryKey parent, string name, bool privileged, bool write)
    {
        using var text = new NativeUnicodeString(name);
        var attributes = new ObjectAttributes
        {
            Length = Marshal.SizeOf<ObjectAttributes>(),
            RootDirectory = parent.Handle.DangerousGetHandle(),
            ObjectName = text.Pointer,
            Attributes = 0x40
        };
        // NtOpenKeyEx cannot create missing keys. OPEN_LINK prevents traversal outside the selected tree.
        var status = NtOpenKeyEx(out var handle, KeyRead | (write ? KeyDelete : 0) | 0x100,
            ref attributes, OpenLink | (privileged ? BackupRestore : 0));
        GC.KeepAlive(parent);
        if (status < 0)
        {
            handle?.Dispose();
            var error = unchecked((int)RtlNtStatusToDosError(status));
            if (error is 2 or 3)
            {
                return null;
            }

            ThrowError(error);
        }
        return RegistryKey.FromHandle(handle!, RegistryView.Registry64);
    }

    private static T WithPrivileges<T>(bool write, bool requireBackup, Func<bool, T> action)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!DuplicateTokenEx(identity.AccessToken, 0x2E, IntPtr.Zero, 2, 2, out var token))
        {
            ThrowError(Marshal.GetLastWin32Error());
        }

        using (token)
        {
            // The process token and the caller's impersonation state are restored/untouched even on failure.
            SetPrivilege(token, "SeRestorePrivilege", enabled: false);
            var backup = SetPrivilege(token, "SeBackupPrivilege", enabled: true);
            var restore = write && SetPrivilege(token, "SeRestorePrivilege", enabled: true);
            if (requireBackup && !backup)
            {
                throw new UnauthorizedAccessException("Для полного резервного копирования нужна привилегия SeBackupPrivilege. Запустите приложение от администратора.");
            }

            return WindowsIdentity.RunImpersonated(token, () => action(backup && (!write || restore)));
        }
    }

    private static bool SetPrivilege(SafeAccessTokenHandle token, string name, bool enabled)
    {
        if (!LookupPrivilegeValue(null, name, out var luid))
        {
            ThrowError(Marshal.GetLastWin32Error());
        }

        var state = new TokenPrivileges { Count = 1, Luid = luid, Attributes = enabled ? 2 : 0 };
        if (!AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero))
        {
            ThrowError(Marshal.GetLastWin32Error());
        }

        return Marshal.GetLastWin32Error() == 0;
    }

    private static void ThrowError(int error)
    {
        var inner = new Win32Exception(error);
        if (error is 5 or 1314)
        {
            throw new UnauthorizedAccessException("Нет доступа к полной записи реестра. Запустите приложение от администратора. " + inner.Message, inner);
        }

        throw new IOException("Ошибка доступа к записи реестра: " + inner.Message, inner);
    }

    private sealed class NativeUnicodeString : IDisposable
    {
        private readonly IntPtr _buffer;
        internal IntPtr Pointer { get; }
        internal NativeUnicodeString(string value)
        {
            if (value.Length > 32766)
            {
                throw new ArgumentException("Слишком длинное имя ключа.", nameof(value));
            }

            _buffer = Marshal.StringToHGlobalUni(value);
            Pointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(new UnicodeString { Length = (ushort)(value.Length * 2), MaximumLength = (ushort)(value.Length * 2 + 2), Buffer = _buffer }, Pointer, false);
        }
        public void Dispose() { Marshal.FreeHGlobal(Pointer); Marshal.FreeHGlobal(_buffer); }
    }

    [StructLayout(LayoutKind.Sequential)] private struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] private struct ObjectAttributes { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)] private struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] private struct TokenPrivileges { public int Count; public Luid Luid; public int Attributes; }
    [DllImport("ntdll.dll")] private static extern int NtOpenKeyEx(out SafeRegistryHandle handle, int desiredAccess, ref ObjectAttributes attributes, int options);
    [DllImport("ntdll.dll")] private static extern int NtDeleteKey(SafeRegistryHandle handle);
    [DllImport("ntdll.dll")] private static extern uint RtlNtStatusToDosError(int status);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] private static extern int RegQueryValueEx(SafeRegistryHandle key, string name, IntPtr reserved, out uint kind, byte[]? data, ref uint size);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] private static extern int RegSaveKeyEx(SafeRegistryHandle key, string file, IntPtr security, int flags);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] private static extern int RegOpenKeyEx(IntPtr key, string subKey, int options, int access, out SafeRegistryHandle handle);
    [DllImport("advapi32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool DuplicateTokenEx(SafeAccessTokenHandle existing, int access, IntPtr attributes, int impersonationLevel, int tokenType, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool LookupPrivilegeValue(string? system, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle token, [MarshalAs(UnmanagedType.Bool)] bool disableAll, ref TokenPrivileges state, int length, IntPtr previous, IntPtr returned);
}
