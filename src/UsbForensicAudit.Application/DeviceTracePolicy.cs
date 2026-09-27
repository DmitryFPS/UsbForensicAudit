using System.Text.Json;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public static class DeviceTracePolicy
{
    private const string Portable = @"SOFTWARE\Microsoft\Windows Portable Devices\Devices\";
    private const string ReadyBoost = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt\";
    private static readonly Regex SystemTrace = new(
        @"^SYSTEM\\(?:CurrentControlSet|ControlSet[0-9]{3})\\Control\\(?:usbflags\\[0-9a-f]{12}|DeviceClasses\\\{[0-9a-f-]{36}\}\\[^\\]+)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static string? NormalizePath(string path)
    {
        var relative = path.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase) ? path[5..]
            : path.StartsWith(@"HKEY_LOCAL_MACHINE\", StringComparison.OrdinalIgnoreCase) ? path[19..] : "";
        if (relative.Length == 0 || relative.Any(c => char.IsControl(c) || c is '*' or '/' or '"')
            || relative.Split('\\').Any(x => x is "" or "." or ".."))
        {
            return null;
        }

        if (SystemTrace.IsMatch(relative)
            || IsLeaf(relative, Portable) || IsLeaf(relative, ReadyBoost)
            || EnumInstanceId(relative) is not null)
        {
            return @"HKEY_LOCAL_MACHINE\" + relative;
        }

        return null;
    }

    public static string? EnumInstanceId(string path)
    {
        var relative = path.StartsWith(@"HKEY_LOCAL_MACHINE\", StringComparison.OrdinalIgnoreCase) ? path[19..]
            : path.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase) ? path[5..] : path;
        const int prefixLength = 26; // SYSTEM\ControlSetNNN\Enum\
        if (!Regex.IsMatch(relative, @"^SYSTEM\\ControlSet[0-9]{3}\\Enum\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            return null;
        }
        var id = relative[prefixLength..];
        return DeviceRemovalPolicy.IsInstanceId(id) ? id : null;
    }

    private static string? NormalizeSourcePath(string path)
    {
        if (NormalizePath(path) is { } normalized)
        {
            return normalized;
        }
        // Старые сканирования дважды дописывали одноуровневый экземпляр WPDBUSENUM.
        var parts = path.Split('\\');
        return parts.Length >= 2 && parts[^1].Equals(parts[^2], StringComparison.OrdinalIgnoreCase)
            && path.Contains(@"\Enum\SWD\WPDBUSENUM\", StringComparison.OrdinalIgnoreCase)
            ? NormalizePath(path[..path.LastIndexOf('\\')]) : null;
    }

    private static bool IsLeaf(string path, string root) => path.StartsWith(root, StringComparison.OrdinalIgnoreCase)
        && path.Length > root.Length && !path[root.Length..].Contains('\\');

    public static IReadOnlyList<string> SourcePaths(UsbDeviceRecord record)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(record.RawJson))
        {
            return [];
        }

        try
        {
            using var document = JsonDocument.Parse(record.RawJson);
            Read(document.RootElement, paths);
        }
        catch (JsonException) { }
        return paths.ToArray();
    }

    private static void Read(JsonElement element, HashSet<string> paths)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var property in element.EnumerateObject())
        {
            if (property.Name == "RegistryPath" && property.Value.ValueKind == JsonValueKind.String)
            {
                if (NormalizeSourcePath(property.Value.GetString()!) is { } path)
                {
                    paths.Add(path);
                }
            }
            else if (property.Name == "RegistryPaths" && property.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var value in property.Value.EnumerateArray())
                {
                    if (value.ValueKind == JsonValueKind.String && NormalizeSourcePath(value.GetString()!) is { } path)
                    {
                        paths.Add(path);
                    }
                }
            }
            else if (property.Name == "MergedRegistryEvidence" && property.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var child in property.Value.EnumerateArray())
                {
                    Read(child, paths);
                }
            }
        }
    }

    public static IReadOnlyList<string> PhysicalIds(string text)
    {
        var parts = DeviceLiveMatcher.NormalizePnpId(text).Split('\\');
        var ids = new List<string>();
        for (var i = 0; i + 2 < parts.Length; i++)
        {
            var bus = parts[i].TrimStart('_', '?');
            if (bus is not "USB" and not "USBSTOR" and not "SCSI")
            {
                continue;
            }

            var id = string.Join('\\', bus, parts[i + 1], parts[i + 2]);
            if (DeviceRemovalPolicy.IsInstanceId(id) && !parts[i + 2].StartsWith('{')
                && (bus != "USB" || parts[i + 1].StartsWith("VID_", StringComparison.Ordinal)))
            {
                ids.Add(id);
            }
        }
        return ids;
    }

    public static DeviceRegistryTrace? Bind(string path, UsbDeviceRecord record, string fingerprint)
    {
        if (NormalizePath(path) is not { } normalized)
        {
            return null;
        }
        if (EnumInstanceId(normalized) is { } enumId
            && DeviceRemovalPolicy.IsInfrastructure(new(enumId, record.DisplayName, false, Service: record.Service)))
        {
            return null;
        }

        if (normalized.Contains(@"\Control\usbflags\", StringComparison.OrdinalIgnoreCase))
        {
            var leaf = normalized[(normalized.LastIndexOf('\\') + 1)..];
            if (!leaf[..4].Equals(record.Vid, StringComparison.OrdinalIgnoreCase)
                || !leaf.Substring(4, 4).Equals(record.Pid, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return new(normalized, fingerprint, [], record.Vid, record.Pid);
        }
        var owners = new[] { record.DeviceInstanceId }.Concat(record.IdentityAliases).SelectMany(PhysicalIds)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var ids = PhysicalIds(EnumInstanceId(normalized) ?? normalized[(normalized.LastIndexOf('\\') + 1)..])
            .Where(owners.Contains).Distinct().ToArray();
        return ids.Length == 0 ? null : new(normalized, fingerprint, ids);
    }

    public static string ProtectionReason(DeviceRegistryTrace trace, IReadOnlyList<DeviceRemovalNode> inventory, Func<string, bool> isPresent)
    {
        if (NormalizePath(trace.RegistryPath) is null)
        {
            return "Неподдерживаемый путь реестра.";
        }

        var modelCache = trace.Vid.Length == 4 && trace.Pid.Length == 4;
        if (!modelCache && trace.DeviceIds.Count == 0)
        {
            return "Связь записи с устройством не подтверждена.";
        }

        var leaf = EnumInstanceId(trace.RegistryPath) ?? trace.RegistryPath[(trace.RegistryPath.LastIndexOf('\\') + 1)..];
        if (modelCache)
        {
            if (!trace.RegistryPath.Contains(@"\Control\usbflags\", StringComparison.OrdinalIgnoreCase)
                || !leaf.StartsWith(trace.Vid + trace.Pid, StringComparison.OrdinalIgnoreCase))
            {
                return "Кэш не соответствует выбранной модели.";
            }
        }
        else if (trace.DeviceIds.Any(id => !PhysicalIds(leaf).Contains(id, StringComparer.OrdinalIgnoreCase)))
        {
            return "Запись не соответствует выбранному экземпляру.";
        }

        var nodes = inventory.Where(x => modelCache
            ? x.InstanceId.Contains($"VID_{trace.Vid}&PID_{trace.Pid}", StringComparison.OrdinalIgnoreCase)
            : trace.DeviceIds.Any(id => PhysicalIds(x.InstanceId).Contains(id, StringComparer.OrdinalIgnoreCase)
                || PhysicalIds(x.AuditInstanceId).Contains(id, StringComparer.OrdinalIgnoreCase))).ToArray();
        var usbEvidence = modelCache || trace.DeviceIds.Any(id => id.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase));
        foreach (var node in nodes)
        {
            var family = DeviceRemovalPolicy.Related(node, inventory);
            var reason = DeviceRemovalPolicy.ProtectionReason(node, family);
            if (reason.Length > 0)
            {
                return reason;
            }
            usbEvidence = true;

            if (family.Any(x => isPresent(x.InstanceId)))
            {
                return "Устройство или его компонент сейчас подключены.";
            }
        }
        if (!usbEvidence)
        {
            return "Связь записи с USB-устройством не подтверждена.";
        }

        return trace.DeviceIds.Any(isPresent) ? "Устройство сейчас подключено." : "";
    }
}
