namespace UsbForensicAudit;

public static class DeviceRemovalPolicy
{
    private static readonly string[] Buses = ["USB", "USBSTOR", "SWD", "SCSI", "HID", "USBPRINT", "STORAGE"];

    public static bool IsInstanceId(string id)
    {
        var parts = id.Split('\\');
        return parts.Length == 3
               && parts.All(p => !string.IsNullOrWhiteSpace(p) && p is not "." and not "..")
               && Buses.Contains(parts[0], StringComparer.OrdinalIgnoreCase)
               && !id.Any(c => char.IsControl(c) || c is '"' or '/' or '*')
               && (!id.Contains('?') || id.StartsWith(@"SWD\WPDBUSENUM\", StringComparison.OrdinalIgnoreCase)
                   || IsUsbVolume(id))
               && (!parts[0].Equals("SWD", StringComparison.OrdinalIgnoreCase)
                   || parts[1].Equals("WPDBUSENUM", StringComparison.OrdinalIgnoreCase));
    }

    public static string NormalizeInstanceId(string id) => DeviceLiveMatcher.NormalizePnpId(id);

    public static bool IsUsbVolume(string id) => id.StartsWith(@"STORAGE\Volume\_??_", StringComparison.OrdinalIgnoreCase)
        && DeviceTracePolicy.PhysicalIds(id).Any(x => x.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
            || x.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase));

    public static bool SameContainer(string left, string right) =>
        Guid.TryParse(left, out var a) && a != Guid.Empty
        && a != new Guid("00000000-0000-0000-ffff-ffffffffffff")
        && Guid.TryParse(right, out var b) && a == b;

    public static IReadOnlyList<DeviceRemovalNode> Related(DeviceRemovalNode node, IReadOnlyList<DeviceRemovalNode> inventory)
    {
        var family = new List<DeviceRemovalNode> { node };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { node.InstanceId };
        for (var i = 0; i < family.Count; i++)
        {
            var member = family[i];
            foreach (var other in inventory)
            {
                if (!seen.Contains(other.InstanceId)
                    && (SameContainer(member.ContainerId, other.ContainerId)
                        || IsChild(member, other) || IsChild(other, member)
                        || IsBackingWrapper(member, other) || IsBackingWrapper(other, member)))
                {
                    seen.Add(other.InstanceId);
                    family.Add(other);
                }
            }
        }
        return family;
    }

    public static string ProtectionReason(DeviceRemovalNode node, IReadOnlyList<DeviceRemovalNode> related)
    {
        if (!IsInstanceId(node.InstanceId) || IsInfrastructure(node) || related.Any(IsInfrastructure))
        {
            return "Системный компонент или инфраструктура шины — только просмотр.";
        }
        if (related.Any(x => x.Present == true))
        {
            return "Устройство или его компонент сейчас подключены.";
        }
        if (node.Present is null || related.Any(x => x.Present is null))
        {
            return "Не удалось достоверно проверить подключение.";
        }
        if (string.IsNullOrWhiteSpace(node.Service) && !Guid.TryParse(node.ClassGuid, out _))
        {
            return "Недостаточно сведений о роли устройства.";
        }
        if (!HasUsbEvidence(node) && !related.Any(HasUsbEvidence))
        {
            return "Связь с USB-устройством не подтверждена.";
        }
        return "";
    }

    private static bool HasUsbEvidence(DeviceRemovalNode node) =>
        node.InstanceId.StartsWith(@"USB\VID_", StringComparison.OrdinalIgnoreCase)
        || node.InstanceId.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase)
        || IsUsbVolume(node.InstanceId)
        || (node.InstanceId.StartsWith(@"SWD\WPDBUSENUM\", StringComparison.OrdinalIgnoreCase)
            && (node.InstanceId.Contains("USB#", StringComparison.OrdinalIgnoreCase)
                || node.InstanceId.Contains("USBSTOR#", StringComparison.OrdinalIgnoreCase)));

    internal static bool IsInfrastructure(DeviceRemovalNode node) =>
        node.InstanceId.StartsWith(@"USB\ROOT_", StringComparison.OrdinalIgnoreCase)
        || node.Service.StartsWith("USBHUB", StringComparison.OrdinalIgnoreCase)
        || node.Service.Contains("XHCI", StringComparison.OrdinalIgnoreCase)
        || node.Service.Contains("EHCI", StringComparison.OrdinalIgnoreCase)
        || node.Service.Contains("OHCI", StringComparison.OrdinalIgnoreCase)
        || node.Service.StartsWith("Usb4", StringComparison.OrdinalIgnoreCase)
        || node.Service.Equals("nhi", StringComparison.OrdinalIgnoreCase);

    private static bool IsChild(DeviceRemovalNode parent, DeviceRemovalNode child)
    {
        if (string.IsNullOrWhiteSpace(parent.ParentIdPrefix) || IsInfrastructure(parent))
        {
            return false;
        }
        var tail = child.InstanceId[(child.InstanceId.LastIndexOf('\\') + 1)..];
        return tail.Equals(parent.ParentIdPrefix, StringComparison.OrdinalIgnoreCase)
               || tail.StartsWith(parent.ParentIdPrefix + "&", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsBackingWrapper(DeviceRemovalNode wrapper, DeviceRemovalNode device) =>
        (wrapper.InstanceId.StartsWith(@"SWD\WPDBUSENUM\", StringComparison.OrdinalIgnoreCase)
            || IsUsbVolume(wrapper.InstanceId))
        && DeviceTracePolicy.PhysicalIds(wrapper.InstanceId).Contains(
            NormalizeInstanceId(device.InstanceId), StringComparer.OrdinalIgnoreCase);
}
