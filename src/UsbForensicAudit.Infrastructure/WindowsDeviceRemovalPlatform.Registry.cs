using System.IO;
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

    public string GetTraceProtectionReason(DeviceRegistryTrace trace)
    {
        if (DeviceTracePolicy.MountedValueName(trace.RegistryPath).Length > 0)
        {
            return MountedVolumeProtectionReason(trace.RegistryPath);
        }
        if (!DeviceTracePolicy.IsVolumeCachePath(trace.RegistryPath))
        {
            return "";
        }

        var path = DeviceTracePolicy.NormalizePath(trace.RegistryPath)!;
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = machine.OpenSubKey(path[19..]);
        if (key is null)
        {
            return "";
        }

        var values = key.GetValueNames().ToDictionary(name => name, name => key.GetValue(name), StringComparer.OrdinalIgnoreCase);
        var snapshot = DeviceTracePolicy.VolumeCacheValuesFingerprint(JsonSerializer.SerializeToElement(values));
        var letter = DeviceTracePolicy.VolumeCacheDriveLetter(path);
        var assigned = DriveInfo.GetDrives().Any(drive => drive.Name.TrimEnd('\\').Equals(letter, StringComparison.OrdinalIgnoreCase));
        return VolumeCacheProtectionReason(trace, snapshot, assigned);
    }

    internal static string VolumeCacheProtectionReason(DeviceRegistryTrace trace, string currentValuesFingerprint, bool driveAssigned)
    {
        if (trace.VolumeCacheSnapshotFingerprint.Length == 0 || currentValuesFingerprint != trace.VolumeCacheSnapshotFingerprint)
        {
            return "Кэш тома изменился со времени сканирования. Выполните новый поиск.";
        }
        return driveAssigned ? "Буква диска из кэша сейчас используется. Отключите носитель и повторите проверку." : "";
    }

    private static string? NativeReadTraceFingerprint(string registryPath) => DeviceTracePolicy.MountedValueName(registryPath).Length > 0
        ? ReadMountedValue(registryPath) is { } bytes ? DeviceTracePolicy.MountedFingerprint(bytes) : null
        : RegistryTraceAccess.ReadFingerprint(registryPath);

    public Task<DeviceRemovalCommandResult> RemoveTraceAsync(DeviceRegistryTrace trace)
    {
        EnsureRemovalSupported();
        var path = DeviceTracePolicy.NormalizePath(trace.RegistryPath) ?? throw new ArgumentException("Неподдерживаемая запись реестра.");
        EnsureInactiveEnumPath(path);
        var reason = DeviceTracePolicy.ProtectionReason(trace, ReadInventory(), IsPresent);
        if (reason.Length == 0)
        {
            reason = GetTraceProtectionReason(trace);
        }
        if (reason.Length > 0)
        {
            throw new InvalidOperationException(reason);
        }

        if (BluetoothCacheIdentity.AddressFromPath(path) is { Length: > 0 } address
            && ReadInventory().Any(node => BluetoothEnumeratorId.DeviceAddress(node.InstanceId) == address))
        {
            throw new InvalidOperationException("Кэш Bluetooth нельзя удалять до удаления PnP-компонентов устройства.");
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

        // Повторная проверка и удаление через дескриптор того же ключа; ACL не меняются.
        if (DeviceTracePolicy.MountedValueName(path).Length > 0)
        {
            RemoveMountedValue(trace);
        }
        else
        {
            RegistryTraceAccess.DeleteTree(path, trace.Fingerprint);
        }
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
