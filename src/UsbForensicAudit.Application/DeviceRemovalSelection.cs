namespace UsbForensicAudit;

internal static class DeviceRemovalSelection
{
    public static bool IsSharedArtifact(UsbDeviceRecord record) => DeviceComposition.IsVolumeMetadata(record)
        || record.DeviceType.Equals("USBFlags", StringComparison.OrdinalIgnoreCase);

    public static HashSet<string> Identities(IEnumerable<UsbDeviceRecord> records) => records
        .SelectMany(source => new[] { source.DeviceInstanceId }.Concat(source.IdentityAliases))
        .SelectMany(id => new[] { id }.Concat(DeviceTracePolicy.PhysicalIds(id)))
        .Select(DeviceRemovalPolicy.NormalizeInstanceId).Where(x => x.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);

    public static DeviceRemovalNode[] Nodes(IEnumerable<UsbDeviceRecord> sources, IReadOnlyList<DeviceRemovalNode> inventory)
    {
        var identifiers = Identities(sources);
        return inventory.Where(node => identifiers.Contains(DeviceRemovalPolicy.NormalizeInstanceId(node.InstanceId))
                || (node.AuditInstanceId.Length > 0 && identifiers.Contains(DeviceRemovalPolicy.NormalizeInstanceId(node.AuditInstanceId)))
                || ((DeviceRemovalPolicy.IsUsbVolume(node.InstanceId)
                        || node.InstanceId.StartsWith(@"SWD\WPDBUSENUM\", StringComparison.OrdinalIgnoreCase))
                    && DeviceTracePolicy.PhysicalIds(node.InstanceId).Any(identifiers.Contains)))
            .SelectMany(node => DeviceRemovalPolicy.Related(node, inventory))
            .DistinctBy(x => x.InstanceId, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static UsbDeviceRecord[] Records(UsbDeviceRecord selected, AuditResult result, IReadOnlyList<DeviceRemovalNode> inventory)
    {
        var sources = result.Devices.Where(x => ReferenceEquals(x, selected)
            || (!string.IsNullOrWhiteSpace(selected.DeviceInstanceId)
                && x.DeviceInstanceId.Equals(selected.DeviceInstanceId, StringComparison.OrdinalIgnoreCase))
            || (!IsSharedArtifact(selected) && !string.IsNullOrWhiteSpace(selected.CanonicalDeviceId)
                && x.CanonicalDeviceId.Equals(selected.CanonicalDeviceId, StringComparison.OrdinalIgnoreCase))).ToHashSet();
        if (IsSharedArtifact(selected))
        {
            return sources.ToArray();
        }

        // Связываем только точные идентификаторы и компоненты из текущего PnP-снимка.
        // Имя, буква диска и одинаковые VID/PID не определяют физический экземпляр.
        while (true)
        {
            var ids = Identities(sources.Where(x => !IsSharedArtifact(x)));
            foreach (var node in Nodes(sources.Where(x => !IsSharedArtifact(x)), inventory))
            {
                ids.Add(DeviceRemovalPolicy.NormalizeInstanceId(node.InstanceId));
                if (node.AuditInstanceId.Length > 0)
                {
                    ids.Add(DeviceRemovalPolicy.NormalizeInstanceId(node.AuditInstanceId));
                }

                ids.UnionWith(DeviceTracePolicy.PhysicalIds(node.InstanceId));
            }
            var additions = result.Devices.Where(x => !sources.Contains(x) && !IsSharedArtifact(x)
                && Identities([x]).Overlaps(ids)).ToArray();
            if (additions.Length == 0)
            {
                return sources.ToArray();
            }

            sources.UnionWith(additions);
        }
    }
}
