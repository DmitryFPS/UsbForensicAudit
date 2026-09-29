using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace UsbForensicAudit;

public sealed partial class WindowsDeviceRemovalPlatform
{
    private static byte[]? ReadMountedValue(string path)
    {
        var name = DeviceTracePolicy.MountedValueName(path);
        if (name.Length == 0) { throw new ArgumentException("Недопустимое сопоставление тома."); }
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = machine.OpenSubKey(@"SYSTEM\MountedDevices");
        var value = key?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (value is null) { return null; }
        return value is byte[] bytes ? bytes : throw new IOException("Изменился тип сопоставления тома.");
    }

    private static string MountedVolumeProtectionReason(string path)
    {
        if (ReadMountedValue(path) is null) { return ""; }
        var name = DeviceTracePolicy.MountedValueName(path);
        var dosName = name.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase) ? name[12..] : name[4..];
        var buffer = new StringBuilder(32768);
        if (QueryDosDevice(dosName, buffer, buffer.Capacity) != 0)
        {
            return "Сопоставление тома сейчас используется Windows. Отключите носитель и повторите проверку.";
        }
        var error = Marshal.GetLastWin32Error();
        return error is 2 or 3 ? "" : "Не удалось проверить использование тома: " + new Win32Exception(error).Message;
    }

    private static void RemoveMountedValue(DeviceRegistryTrace trace)
    {
        var reason = MountedVolumeProtectionReason(trace.RegistryPath);
        if (reason.Length > 0) { throw new IOException(reason); }
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = machine.OpenSubKey(@"SYSTEM\MountedDevices", writable: true);
        if (key is null) { return; }
        var name = DeviceTracePolicy.MountedValueName(trace.RegistryPath);
        if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not { } value) { return; }
        if (value is not byte[] bytes || DeviceTracePolicy.MountedFingerprint(bytes) != trace.Fingerprint)
        {
            throw new IOException("Сопоставление тома изменилось. Удаление отменено.");
        }
        key.DeleteValue(name, throwOnMissingValue: false);
    }

    internal static string MountedValueExport(DeviceRegistryTrace trace)
    {
        var name = DeviceTracePolicy.MountedValueName(trace.RegistryPath);
        if (name.Length == 0 || trace.MountedValueSnapshot.Length == 0)
        {
            throw new ArgumentException("Нет снимка выбранного значения реестра.");
        }
        var bytes = Convert.FromBase64String(trace.MountedValueSnapshot);
        if (DeviceTracePolicy.MountedFingerprint(bytes) != trace.Fingerprint)
        {
            throw new IOException("Снимок сопоставления тома изменился.");
        }
        return "Windows Registry Editor Version 5.00\r\n\r\n[" + DeviceTracePolicy.MountedRoot + "]\r\n\""
            + name.Replace("\\", "\\\\", StringComparison.Ordinal) + "\"=hex:"
            + string.Join(',', bytes.Select(x => x.ToString("x2"))) + "\r\n";
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string deviceName, StringBuilder target, int max);
}
