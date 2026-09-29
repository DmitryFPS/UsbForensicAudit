using System.IO;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace UsbForensicAudit;

public static partial class SetupApiDeviceRelations
{
    public static void Apply(IEnumerable<UsbDeviceRecord> devices, IEnumerable<EvidenceRecord> evidence)
    {
        var records = devices.ToArray();
        var parents = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in evidence)
        {
            if (record.Provider.Equals("SetupAPI", StringComparison.OrdinalIgnoreCase))
            {
                ReadParents(record.RawText, parents);
            }
            else if (record.Provider.Equals("Microsoft-Windows-Kernel-PnP", StringComparison.OrdinalIgnoreCase) && record.EventId == "400")
            {
                ReadEventParent(record.RawText, parents);
            }
        }

        foreach (var device in records)
        {
            if (!string.IsNullOrWhiteSpace(device.ParentDeviceInstanceId)
                || !parents.TryGetValue(device.DeviceInstanceId, out var candidates)
                || candidates.Count != 1)
            {
                continue;
            }

            var parent = candidates.Single();
            if (IsSupportedParent(device.DeviceInstanceId, parent))
            {
                device.ParentDeviceInstanceId = parent;
            }
        }
        foreach (var device in records.Where(x => IsStorageUsbParent(x.DeviceInstanceId, x.ParentDeviceInstanceId)))
        {
            // В старой базе диск мог ошибочно сохраниться как внутренний и исчезнуть из обычного списка.
            DeviceTransportClassifier.Classify(device);
        }
    }

    private static void ReadEventParent(string xml, Dictionary<string, HashSet<string>> parents)
    {
        try
        {
            var root = XDocument.Parse(xml).Root;
            var system = root?.Elements().SingleOrDefault(x => x.Name.LocalName == "System");
            if (system?.Elements().SingleOrDefault(x => x.Name.LocalName == "Provider")?.Attribute("Name")?.Value != "Microsoft-Windows-Kernel-PnP"
                || system.Elements().SingleOrDefault(x => x.Name.LocalName == "EventID")?.Value != "400")
            {
                return;
            }
            var fields = root!.Elements().SingleOrDefault(x => x.Name.LocalName == "EventData")?.Elements()
                .Where(x => x.Name.LocalName == "Data").ToArray() ?? [];
            var children = fields.Where(x => x.Attribute("Name")?.Value == "DeviceInstanceId").ToArray();
            var parentFields = fields.Where(x => x.Attribute("Name")?.Value == "ParentDeviceInstanceId").ToArray();
            if (children.Length != 1 || parentFields.Length != 1) { return; }
            var child = children[0].Value;
            if (!parents.TryGetValue(child, out var candidates)) { parents[child] = candidates = new(StringComparer.OrdinalIgnoreCase); }
            candidates.Add(parentFields[0].Value);
        }
        catch (Exception ex) when (ex is XmlException or InvalidOperationException) { }
    }

    internal static bool IsSupportedParent(string child, string parent) => IsCompositeParent(child, parent) || IsStorageUsbParent(child, parent);

    internal static bool IsStorageUsbParent(string child, string parent) => child.StartsWith(@"SCSI\DISK&", StringComparison.OrdinalIgnoreCase)
        && DeviceRemovalPolicy.IsInstanceId(child) && PhysicalDeviceRegex().IsMatch(parent) && DeviceRemovalPolicy.IsInstanceId(parent);

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
