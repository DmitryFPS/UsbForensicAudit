using System.IO;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public static partial class SetupApiDeviceRelations
{
    public static void Apply(IEnumerable<UsbDeviceRecord> devices, IEnumerable<EvidenceRecord> evidence)
    {
        var parents = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in evidence.Where(x => x.Provider.Equals("SetupAPI", StringComparison.OrdinalIgnoreCase)))
        {
            ReadParents(record.RawText, parents);
        }

        foreach (var device in devices)
        {
            if (!string.IsNullOrWhiteSpace(device.ParentDeviceInstanceId)
                || !parents.TryGetValue(device.DeviceInstanceId, out var candidates)
                || candidates.Count != 1)
            {
                continue;
            }

            var parent = candidates.Single();
            if (IsCompositeParent(device.DeviceInstanceId, parent))
            {
                device.ParentDeviceInstanceId = parent;
            }
        }
    }

    private static void ReadParents(string rawText, Dictionary<string, HashSet<string>> parents)
    {
        // Сохранённые EvidenceRecord содержат также однострочный текст секции:
        // восстанавливаем границы маркеров, не сопоставляя произвольные части ID.
        var text = Regex.Replace(rawText, @"[ \t]+(?=(?:>>>|<<<|dvi:))", "\n", RegexOptions.CultureInvariant);
        using var reader = new StringReader(text);
        var sectionDevice = "";
        var blockDevice = "";
        for (var line = reader.ReadLine(); line is not null; line = reader.ReadLine())
        {
            if (line.StartsWith(">>>  [", StringComparison.Ordinal)
                || Regex.IsMatch(line, @"^>>>\s+\[", RegexOptions.CultureInvariant))
            {
                var header = SectionDeviceRegex().Match(line);
                sectionDevice = header.Success ? header.Groups["id"].Value.Trim() : "";
                blockDevice = "";
                continue;
            }

            if (line.StartsWith("<<<", StringComparison.Ordinal))
            {
                sectionDevice = "";
                blockDevice = "";
                continue;
            }

            var block = DeviceBlockRegex().Match(line);
            if (block.Success)
            {
                blockDevice = block.Groups["id"].Value.Trim();
                continue;
            }
            if (Regex.IsMatch(line, @"^\s*dvi:\s*\{(?:Install|Configure) Device - exit\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            {
                blockDevice = "";
                continue;
            }

            var parent = ParentDeviceRegex().Match(line);
            if (!parent.Success || sectionDevice.Length == 0
                || !blockDevice.Equals(sectionDevice, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!parents.TryGetValue(sectionDevice, out var candidates))
            {
                parents[sectionDevice] = candidates = new(StringComparer.OrdinalIgnoreCase);
            }
            // Keep unsupported and conflicting parents in the set too: a second
            // historical parent must not silently turn into a definite relationship.
            candidates.Add(parent.Groups["id"].Value.Trim().ToUpperInvariant());
        }
    }

    internal static bool IsCompositeParent(string child, string parent)
    {
        var childMatch = CompositeDeviceRegex().Match(child);
        var parentMatch = PhysicalDeviceRegex().Match(parent);
        return childMatch.Success && parentMatch.Success
               && childMatch.Groups["model"].Value.Equals(parentMatch.Groups["model"].Value, StringComparison.OrdinalIgnoreCase)
               && DeviceRemovalPolicy.IsInstanceId(child) && DeviceRemovalPolicy.IsInstanceId(parent);
    }

    [GeneratedRegex(@"^>>>\s+\[Device Install(?:\s+\([^\]\r\n]*\))?\s+-\s+(?<id>USB\\[^\]\r\n]+)\]\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SectionDeviceRegex();

    [GeneratedRegex(@"^\s*dvi:\s*\{(?:Install|Configure) Device\s+-\s+(?<id>[^}\r\n]+)\}(?:\s+[0-9:.]+)?\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DeviceBlockRegex();

    [GeneratedRegex(@"^\s*dvi:\s*Parent Device:\s*(?<id>\S+)\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ParentDeviceRegex();

    [GeneratedRegex(@"^USB\\(?<model>VID_[0-9A-F]{4}&PID_[0-9A-F]{4})(?:&REV_[0-9A-F]{4})?&MI_[0-9A-F]{2}\\[^\\\s]+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CompositeDeviceRegex();

    [GeneratedRegex(@"^USB\\(?<model>VID_[0-9A-F]{4}&PID_[0-9A-F]{4})(?:&REV_[0-9A-F]{4})?\\[^\\\s]+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PhysicalDeviceRegex();
}
