using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace UsbForensicAudit;

public sealed partial class WindowsDeviceRemovalPlatform
{
    public bool IsActiveEnumPath(string registryPath)
    {
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var select = machine.OpenSubKey(@"SYSTEM\Select");
        if (select?.GetValue("Current") is not int current || current is < 1 or > 999)
        {
            throw new IOException("Не удалось определить активный набор настроек Windows.");
        }
        return IsActiveEnumPath(registryPath, current);
    }

    internal static bool IsActiveEnumPath(string registryPath, int current)
    {
        if (current is < 1 or > 999)
        {
            throw new ArgumentOutOfRangeException(nameof(current));
        }

        var normalized = DeviceTracePolicy.NormalizePath(registryPath);
        return normalized is null || DeviceTracePolicy.EnumInstanceId(normalized) is null
            || normalized.StartsWith($@"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet{current:D3}\", StringComparison.OrdinalIgnoreCase);
    }

    public string? ReadTraceFingerprint(string registryPath)
        => _readTrace(DeviceTracePolicy.NormalizePath(registryPath) ?? throw new ArgumentException("Неподдерживаемая запись реестра."));

    private static string? NativeReadTraceFingerprint(string registryPath)
    {
        var path = DeviceTracePolicy.NormalizePath(registryPath) ?? throw new ArgumentException("Неподдерживаемая запись реестра.");
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = machine.OpenSubKey(path[19..]);
        if (key is null)
        {
            return null;
        }

        var content = new StringBuilder();
        var remaining = 4096;
        AppendKey(key, content, 0, ref remaining);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content.ToString())));
    }

    private static void AppendKey(RegistryKey key, StringBuilder content, int depth, ref int remaining)
    {
        if (depth > 16 || --remaining < 0)
        {
            throw new IOException("Запись слишком велика для выборочного удаления.");
        }

        content.Append(JsonSerializer.Serialize(key.Name));
        foreach (var name in key.GetValueNames().Order(StringComparer.OrdinalIgnoreCase))
        {
            if (--remaining < 0)
            {
                throw new IOException("Запись содержит слишком много значений.");
            }

            content.Append(JsonSerializer.Serialize(new
            {
                Name = name,
                Kind = key.GetValueKind(name),
                Value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames)
            }));
        }
        foreach (var name in key.GetSubKeyNames().Order(StringComparer.OrdinalIgnoreCase))
        {
            using var child = key.OpenSubKey(name) ?? throw new IOException("Состав записи изменился при чтении.");
            AppendKey(child, content, depth + 1, ref remaining);
        }
    }

    public Task<DeviceRemovalCommandResult> RemoveTraceAsync(DeviceRegistryTrace trace)
    {
        EnsureRemovalSupported();
        var path = DeviceTracePolicy.NormalizePath(trace.RegistryPath) ?? throw new ArgumentException("Неподдерживаемая запись реестра.");
        EnsureInactiveEnumPath(path);
        var reason = DeviceTracePolicy.ProtectionReason(trace, ReadInventory(), IsPresent);
        if (reason.Length > 0)
        {
            throw new InvalidOperationException(reason);
        }

        var current = ReadTraceFingerprint(path);
        if (current is null)
        {
            return Task.FromResult(new DeviceRemovalCommandResult(0, "Запись уже отсутствует."));
        }

        if (current != trace.Fingerprint)
        {
            throw new IOException("Запись реестра изменилась. Удаление отменено.");
        }

        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        // Только явно выбранный конечный ключ. Права/владельцы реестра не меняются.
        machine.DeleteSubKeyTree(path[19..], throwOnMissingSubKey: false);
        return Task.FromResult(new DeviceRemovalCommandResult(ReadTraceFingerprint(path) is null ? 0 : 1, ""));
    }

    private void EnsureInactiveEnumPath(string path)
    {
        if (DeviceTracePolicy.EnumInstanceId(path) is not null && IsActiveEnumPath(path))
        {
            throw new IOException("Активные PnP-записи удаляются только штатной командой Windows.");
        }
    }
}
