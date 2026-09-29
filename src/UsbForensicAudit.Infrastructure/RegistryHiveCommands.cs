using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace UsbForensicAudit;

/// <summary>Загрузка только временных копий; Unicode и числовой код ошибки не теряются в reg.exe.</summary>
internal static class RegistryHiveCommands
{
    internal static (int ExitCode, string Output) Run(string action, string key, string? hive = null)
    {
        var parts = key.Split('\\');
        if (parts.Length != 2 || !parts[1].StartsWith("UFA_", StringComparison.Ordinal)
            || (parts[0] != "HKU" && parts[0] != "HKLM") || (action != "load" && action != "unload"))
            throw new ArgumentException("Допустима только временная точка загрузки UFA_ в HKU/HKLM.");

        var root = new IntPtr(parts[0] == "HKU" ? unchecked((int)0x80000003) : unchecked((int)0x80000002));
        int error;
        if (action == "load")
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(hive);
            if (!File.Exists(hive)) return (2, $"Файл копии куста не найден: {hive} (Win32 2)");
            // reg.exe ограничивает путь к файлу; Unicode API принимает расширенный путь.
            error = RegLoadKey(root, parts[1], ExtendedPath(hive));
        }
        else
        {
            error = RegUnLoadKey(root, parts[1]);
        }
        return (error, error == 0 ? "" : $"{new Win32Exception(error).Message} (Win32 {error}; {action} {key})");
    }

    internal static string ExtendedPath(string path)
    {
        var full = Path.GetFullPath(path);
        if (full.StartsWith(@"\\?\", StringComparison.Ordinal)) return full;
        return full.StartsWith(@"\\", StringComparison.Ordinal)
            ? @"\\?\UNC\" + full[2..] : @"\\?\" + full;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegLoadKey(IntPtr root, string subKey, string file);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegUnLoadKey(IntPtr root, string subKey);
}
