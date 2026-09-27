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
            || IsLeaf(relative, Portable) || IsLeaf(relative, ReadyBoost))
        {
            return @"HKEY_LOCAL_MACHINE\" + relative;
        }

        return null;
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
                if (NormalizePath(property.Value.GetString()!) is { } path)
                {
                    paths.Add(path);
                }
            }
            else if (property.Name == "RegistryPaths" && property.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var value in property.Value.EnumerateArray())
                {
                    if (value.ValueKind == JsonValueKind.String && NormalizePath(value.GetString()!) is { } path)
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
        var ids = PhysicalIds(normalized[(normalized.LastIndexOf('\\') + 1)..]).Where(owners.Contains).Distinct().ToArray();
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

        var leaf = trace.RegistryPath[(trace.RegistryPath.LastIndexOf('\\') + 1)..];
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
        foreach (var node in nodes)
        {
            var family = DeviceRemovalPolicy.Related(node, inventory);
            var reason = DeviceRemovalPolicy.ProtectionReason(node, family);
            if (reason.Length > 0)
            {
                return reason;
            }

            if (family.Any(x => isPresent(x.InstanceId)))
            {
                return "Устройство или его компонент сейчас подключены.";
            }
        }
        return trace.DeviceIds.Any(isPresent) ? "Устройство сейчас подключено." : "";
    }
}
