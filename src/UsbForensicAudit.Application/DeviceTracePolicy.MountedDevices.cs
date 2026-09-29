using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public static partial class DeviceTracePolicy
{
    internal const string MountedRoot = @"HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices";

    public static string MountedValueName(string path)
    {
        var full = path.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase) ? @"HKEY_LOCAL_MACHINE\" + path[5..] : path;
        if (!full.StartsWith(MountedRoot + @"\", StringComparison.OrdinalIgnoreCase))
        {
            return "";
        }
        var name = full[(MountedRoot.Length + 1)..];
        return Regex.IsMatch(name, @"^\\DosDevices\\[A-Z]:$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
            || Regex.IsMatch(name, @"^\\\?\?\\Volume\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) ? name : "";
    }

    internal static string MountedFingerprint(byte[] data) => Convert.ToHexString(SHA256.HashData(data));

    internal static IReadOnlyList<string> MountedDeviceIds(UsbDeviceRecord record)
        => ReadMountedSnapshot(record) is { } data ? MountedDeviceIds(data) : [];

    internal static IReadOnlyList<string> MountedDeviceIds(byte[] data)
    {
        if (data.Length is 0 or > 32768 || data.Length % 2 != 0)
        {
            return [];
        }
        var text = Encoding.Unicode.GetString(data).TrimEnd('\0');
        if (!text.StartsWith("_??_USB#", StringComparison.OrdinalIgnoreCase)
            && !text.StartsWith("_??_USBSTOR#", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }
        return PhysicalIds(text).Where(x => x.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
            || x.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static byte[]? ReadMountedSnapshot(UsbDeviceRecord record)
    {
        var name = MountedValueName(record.DeviceInstanceId);
        if (name.Length == 0 || !record.DeviceType.Equals("VolumeMapping", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        try
        {
            using var document = JsonDocument.Parse(record.RawJson);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("MappingName", out var mapping)
                || mapping.ValueKind != JsonValueKind.String || !name.Equals(mapping.GetString(), StringComparison.OrdinalIgnoreCase)
                || !root.TryGetProperty("RawBinaryBase64", out var raw) || raw.ValueKind != JsonValueKind.String)
            {
                return null;
            }
            return Convert.FromBase64String(raw.GetString()!);
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return null;
        }
    }

    private static DeviceRegistryTrace? BindMountedValue(string path, UsbDeviceRecord record, string fingerprint)
    {
        if (!path.Equals(NormalizePath(record.DeviceInstanceId), StringComparison.OrdinalIgnoreCase)
            || ReadMountedSnapshot(record) is not { } bytes || MountedDeviceIds(bytes) is not { Count: > 0 } ids)
        {
            return null;
        }
        return new(path, fingerprint, ids, MountedValueSnapshot: Convert.ToBase64String(bytes));
    }

    internal static string MountedProtectionReason(DeviceRegistryTrace trace, IReadOnlyList<DeviceRemovalNode> inventory, Func<string, bool> isPresent)
    {
        byte[] bytes;
        try { bytes = Convert.FromBase64String(trace.MountedValueSnapshot); }
        catch (FormatException) { return "Не подтверждён снимок сопоставления тома."; }
        var ids = MountedDeviceIds(bytes);
        if (ids.Count == 0 || !ids.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(trace.DeviceIds)
            || trace.Vid.Length > 0 || trace.Pid.Length > 0)
        {
            return "Не подтверждена связь сопоставления тома с USB-устройством.";
        }
        if (trace.Fingerprint.Length > 0 && trace.Fingerprint != MountedFingerprint(bytes))
        {
            return "Сопоставление тома изменилось со времени сканирования. Выполните новый поиск.";
        }
        var records = ids.Select(id => new UsbDeviceRecord { DeviceInstanceId = id });
        foreach (var node in DeviceRemovalSelection.Nodes(records, inventory))
        {
            var family = DeviceRemovalPolicy.Related(node, inventory);
            var reason = DeviceRemovalPolicy.ProtectionReason(node, family);
            if (reason.Length > 0) { return reason; }
            if (family.Any(x => isPresent(x.InstanceId))) { return "Устройство или его компонент сейчас подключены."; }
        }
        return ids.Any(isPresent) ? "Устройство сейчас подключено." : "";
    }
}
