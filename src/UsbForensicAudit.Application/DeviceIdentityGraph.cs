using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public static class DeviceIdentityGraph
{
    private static readonly Regex GeneratedInstanceRegex = new(
        @"^\d+&[0-9A-F]+&\d+(?:&\d+)+$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex CompositeInterfaceRegex = new(
        @"&MI_[0-9A-F]{2}",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static void Process(IList<UsbDeviceRecord> devices)
    {
        if (devices.Count == 0)
        {
            return;
        }

        var union = new UnionFind(devices.Count);
        JoinByStrongKey(devices, union, "instance", d => NormalizeInstance(d.DeviceInstanceId));
        JoinByAliases(devices, union);
        JoinByStrongKey(devices, union, "container", d => NormalizeContainer(d.ContainerId));
        JoinByStrongKey(devices, union, "serial", d => IsHardwareSerial(d.Serial) ? NormalizeSerial(d.Serial) : "");
        JoinByStrongKey(devices, union, "topology", d => NormalizeTopology(d.ParentIdPrefix, d.LocationPaths));
        JoinByStrongKey(devices, union, "composite-parent", CompositeParentKey);
        JoinByStrongKey(devices, union, "composite-child", CompositeChildKey);

        var groups = Enumerable.Range(0, devices.Count)
            .GroupBy(union.Find)
            .Select(g => g.ToList())
            .ToList();

        // usbflags only identifies a product. It may join an existing physical device only
        // when VID/PID resolves to exactly one already-established physical group.
        foreach (var index in Enumerable.Range(0, devices.Count).Where(i => IsUsbFlags(devices[i])))
        {
            var candidates = groups
                .Where(g => g.Any(i => !IsUsbFlags(devices[i]) && SameVidPid(devices[i], devices[index])))
                .ToArray();
            if (candidates.Length == 1)
            {
                union.Union(index, candidates[0][0]);
            }
        }

        foreach (var group in Enumerable.Range(0, devices.Count).GroupBy(union.Find))
        {
            var members = group.Select(i => devices[i]).ToArray();
            var primary = members.OrderByDescending(PrimaryScore).ThenBy(d => d.DeviceInstanceId, StringComparer.OrdinalIgnoreCase).First();
            var canonicalId = BuildCanonicalId(members);
            var linkedIds = members.Select(d => d.DeviceInstanceId)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var provenance = BuildProvenance(members);
            var confidence = provenance.Any(x => x.StartsWith("ContainerID", StringComparison.Ordinal)) ? "High"
                : provenance.Any(x => x.StartsWith("HardwareSerial", StringComparison.Ordinal)) ? "High"
                : provenance.Any(x => x.StartsWith("Topology", StringComparison.Ordinal)) ? "Medium"
                : "SingleSource";

            foreach (var member in members)
            {
                member.CanonicalDeviceId = canonicalId;
                member.PhysicalDeviceGroup = canonicalId;
                member.IsCanonicalPrimary = ReferenceEquals(member, primary);
                member.IdentityConfidence = confidence;
                member.LinkedSourceIds = [.. linkedIds];
                member.IdentityProvenance = [.. provenance];
            }

            BorrowNameForGroup(primary, members);
        }
    }

    public static bool IsHardwareSerial(string? value)
    {
        var serial = NormalizeSerial(value ?? "");
        if (serial.Length < 4 || GeneratedInstanceRegex.IsMatch(serial))
        {
            return false;
        }

        return !Guid.TryParse(serial.Trim('{', '}'), out _)
               && !serial.StartsWith("SWD", StringComparison.OrdinalIgnoreCase)
               && !serial.Equals("00000000", StringComparison.OrdinalIgnoreCase);
    }

    public static string NormalizeSerial(string value)
    {
        var normalized = value.Trim().Trim('{', '}').ToUpperInvariant();
        return normalized.EndsWith("&0", StringComparison.Ordinal) ? normalized[..^2] : normalized;
    }

    /// <summary>
    /// Узел WPD и запись из Enum описывают одно устройство: связываем их по
    /// идентификатору экземпляра, объявленному записью как псевдоним.
    /// </summary>
    private static void JoinByAliases(IList<UsbDeviceRecord> devices, UnionFind union)
    {
        var byInstance = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < devices.Count; i++)
        {
            if (IsUsbFlags(devices[i]))
            {
                continue;
            }

            var key = NormalizeInstance(devices[i].DeviceInstanceId);
            if (!string.IsNullOrWhiteSpace(key))
            {
                byInstance.TryAdd(key, i);
            }
        }

        for (var i = 0; i < devices.Count; i++)
        {
            if (IsUsbFlags(devices[i]))
            {
                continue;
            }

            foreach (var alias in devices[i].IdentityAliases)
            {
                var key = NormalizeInstance(alias);
                if (!string.IsNullOrWhiteSpace(key) && byInstance.TryGetValue(key, out var other) && other != i)
                {
                    union.Union(i, other);
                }
            }
        }
    }

    private static void JoinByStrongKey(
        IList<UsbDeviceRecord> devices,
        UnionFind union,
        string kind,
        Func<UsbDeviceRecord, string> selector)
    {
        var first = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < devices.Count; i++)
        {
            if (IsUsbFlags(devices[i]))
            {
                continue;
            }

            var key = selector(devices[i]);
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            if (first.TryGetValue($"{kind}:{key}", out var other))
            {
                union.Union(i, other);
            }
            else
            {
                first[$"{kind}:{key}"] = i;
            }
        }
    }

    private static List<string> BuildProvenance(IReadOnlyList<UsbDeviceRecord> members)
    {
        var result = new List<string>();
        AddShared(result, "ContainerID", members.Select(x => NormalizeContainer(x.ContainerId)));
        AddShared(result, "HardwareSerial", members.Select(x => IsHardwareSerial(x.Serial) ? NormalizeSerial(x.Serial) : ""));
        AddShared(result, "Topology", members.Select(x => NormalizeTopology(x.ParentIdPrefix, x.LocationPaths)));
        AddShared(result, "ExactInstanceId", members.Select(x => NormalizeInstance(x.DeviceInstanceId)));
        if (members.Any(IsUsbFlags) && members.Any(x => !IsUsbFlags(x)))
        {
            result.Add("usbflags: unique VID/PID candidate (weak supporting link)");
        }

        if (result.Count == 0)
        {
            result.Add("No cross-source strong key; record retained independently");
        }

        return result;
    }

    private static void AddShared(List<string> output, string label, IEnumerable<string> values)
    {
        foreach (var group in values.Where(x => !string.IsNullOrWhiteSpace(x)).GroupBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            if (group.Count() > 1)
            {
                output.Add($"{label}: {group.Key}");
            }
        }
    }

    private static string BuildCanonicalId(IReadOnlyList<UsbDeviceRecord> members)
    {
        // Ключ выбирается детерминированно, иначе один и тот же носитель получает
        // разные идентификаторы в разных прогонах и отчёты нельзя сопоставить.
        var key = members.Select(x => IsHardwareSerial(x.Serial) ? $"SERIAL:{NormalizeSerial(x.Serial)}" : "")
                      .Where(x => x.Length > 0).OrderBy(x => x, StringComparer.Ordinal).FirstOrDefault()
                  ?? members.Select(x => NormalizeContainer(x.ContainerId))
                      .Where(x => x.Length > 0).Select(x => $"CONTAINER:{x}")
                      .OrderBy(x => x, StringComparer.Ordinal).FirstOrDefault()
                  ?? members.Select(x => NormalizeTopology(x.ParentIdPrefix, x.LocationPaths))
                      .Where(x => x.Length > 0).OrderBy(x => x, StringComparer.Ordinal).FirstOrDefault()
                  ?? members.Select(x => NormalizeInstance(x.DeviceInstanceId))
                      .Where(x => x.Length > 0).OrderBy(x => x, StringComparer.Ordinal).FirstOrDefault()
                  ?? string.Join('|', members.Select(x => x.Source).OrderBy(x => x, StringComparer.Ordinal));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        return $"DEV-{Convert.ToHexString(hash.AsSpan(0, 10))}";
    }

    /// <summary>
    /// Список показывает устройство одной строкой, поэтому в главной записи
    /// должно стоять имя вещи. Windows называет родительскую запись по классу —
    /// «USB Composite Device», — а модель пишет у функции: у встроенной камеры
    /// это «Integrated Camera». Имя берётся у соседней записи того же
    /// устройства, и откуда оно взято, записано в происхождении.
    /// </summary>
    private static void BorrowNameForGroup(UsbDeviceRecord primary, IReadOnlyList<UsbDeviceRecord> members)
    {
        primary.GroupDisplayName = "";
        if (members.Count < 2 || !DeviceNameQuality.IsClassName(primary.OwnDisplayName))
        {
            return;
        }

        var donor = members
            .Where(x => !ReferenceEquals(x, primary) && !IsUsbFlags(x))
            .Where(x => !DeviceNameQuality.IsClassName(x.OwnDisplayName))
            .OrderBy(x => x.DeviceInstanceId, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
        if (donor is null)
        {
            return;
        }

        primary.GroupDisplayName = donor.OwnDisplayName;
        primary.IdentityProvenance.Add(
            $"Имя показано по записи функции того же устройства: {donor.DeviceInstanceId}");
    }

    /// <summary>
    /// Главной в группе становится запись самого устройства. Услуга Bluetooth и
    /// грань составного устройства проигрывают своему устройству: список
    /// показывает главную запись, и «USB Input Device» вместо составного
    /// устройства сбивает читателя с толку.
    /// </summary>
    private static int PrimaryScore(UsbDeviceRecord device) =>
        (device.VisualCategory == "RealUsb" ? 100 : 0)
        + (device.Source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase) ? 30 : 0)
        + (device.Source.Equals("Registry: USB", StringComparison.OrdinalIgnoreCase) ? 20 : 0)
        + (device.IsCurrentlyConnected ? 10 : 0)
        + (DeviceComposition.IsPartOfAnotherDevice(device) ? -60 : 0)
        + (IsUsbFlags(device) ? -100 : 0);

    private static string NormalizeInstance(string value) =>
        DevicePathNormalizer.CanonicalDeviceId(value, replaceHashes: true);

    private static string CompositeParentKey(UsbDeviceRecord device)
    {
        if (!device.DeviceInstanceId.StartsWith(@"USB\VID_", StringComparison.OrdinalIgnoreCase))
        {
            return "";
        }

        return CompositeInterfaceRegex.Replace(NormalizeInstance(device.DeviceInstanceId), "");
    }

    /// <summary>
    /// Грани составного устройства и само устройство сходятся по родительскому
    /// префиксу. Windows выдаёт устройству префикс «6&amp;3ad2d465&amp;0» и из него
    /// строит идентификаторы его граней: «…&amp;MI_00\6&amp;3ad2d465&amp;0&amp;0000».
    ///
    /// Без этого ключа встроенная камера ноутбука распадается на три записи:
    /// «USB Composite Device», «Integrated Camera» и «APP Mode» — три строки
    /// списка вместо одной камеры. По одному лишь пути они не сходятся: у
    /// самого устройства в пути стоит его серийный номер, а у граней —
    /// выданный Windows номер, и общего в них нет.
    /// </summary>
    private static string CompositeChildKey(UsbDeviceRecord device)
    {
        var id = device.DeviceInstanceId.Trim();
        if (!id.StartsWith(@"USB\VID_", StringComparison.OrdinalIgnoreCase))
        {
            return "";
        }

        var separator = id.LastIndexOf('\\');
        if (separator <= 4)
        {
            return "";
        }

        var product = CompositeInterfaceRegex.Replace(id[4..separator], "").ToUpperInvariant();
        if (CompositeInterfaceRegex.IsMatch(id))
        {
            var instance = id[(separator + 1)..];
            var cut = instance.LastIndexOf('&');
            return cut > 0 ? $"{product}|{instance[..cut].ToUpperInvariant()}" : "";
        }

        var prefix = device.ParentIdPrefix.Trim();
        return prefix.Length >= 5 ? $"{product}|{prefix.ToUpperInvariant()}" : "";
    }

    /// <summary>
    /// Windows выдаёт {00000000-0000-0000-FFFF-FFFFFFFFFFFF} всем устройствам,
    /// у которых контейнера нет. Склейка по этому значению объединяет в одно
    /// устройство весь набор встроенного оборудования, поэтому оно не идентификатор.
    /// </summary>
    private static readonly HashSet<string> NonIdentifyingContainerIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "00000000-0000-0000-0000-000000000000",
        "00000000-0000-0000-FFFF-FFFFFFFFFFFF"
    };

    private static string NormalizeContainer(string value)
    {
        if (!Guid.TryParse(value.Trim(), out var parsed))
        {
            return "";
        }

        var normalized = parsed.ToString("D").ToUpperInvariant();
        return NonIdentifyingContainerIds.Contains(normalized) ? "" : normalized;
    }

    private static string NormalizeTopology(string parent, string locationPaths)
    {
        var normalizedParent = parent.Trim().ToUpperInvariant();
        if (normalizedParent.Length >= 5)
        {
            return $"PARENT:{normalizedParent}";
        }

        var path = locationPaths.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault();
        return string.IsNullOrWhiteSpace(path) ? "" : $"PATH:{path.ToUpperInvariant()}";
    }

    private static bool SameVidPid(UsbDeviceRecord left, UsbDeviceRecord right) =>
        !string.IsNullOrWhiteSpace(left.Vid) && !string.IsNullOrWhiteSpace(left.Pid)
        && left.Vid.Equals(right.Vid, StringComparison.OrdinalIgnoreCase)
        && left.Pid.Equals(right.Pid, StringComparison.OrdinalIgnoreCase);

    private static bool IsUsbFlags(UsbDeviceRecord device) =>
        device.VisualCategory.Equals("UsbFlagsTrace", StringComparison.OrdinalIgnoreCase)
        || device.Source.Contains("usbflags", StringComparison.OrdinalIgnoreCase);

    private sealed class UnionFind(int count)
    {
        private readonly int[] _parent = Enumerable.Range(0, count).ToArray();

        public int Find(int value)
        {
            if (_parent[value] != value)
            {
                _parent[value] = Find(_parent[value]);
            }
            return _parent[value];
        }

        public void Union(int left, int right)
        {
            var leftRoot = Find(left);
            var rightRoot = Find(right);
            if (leftRoot != rightRoot)
            {
                _parent[rightRoot] = leftRoot;
            }
        }
    }
}
