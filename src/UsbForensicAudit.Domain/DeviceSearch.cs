namespace UsbForensicAudit;

public static class DeviceSearch
{
    public static bool Matches(UsbDeviceRecord device, string? query)
        => Matches([device], query);

    public static bool Matches(IEnumerable<UsbDeviceRecord> devices, string? query)
    {
        var text = string.Join(" ", devices.Select(device => string.Join(" ", device.DisplayName, device.FriendlyName, device.InstanceSummary, device.DeviceInstanceId, device.Vid, device.Pid,
            device.Serial, device.Manufacturer, device.Product, device.Source, device.CategoryText,
            string.Join(" ", device.IdentityAliases))));
        text = text.Replace('#', '\\');
        return (query ?? "").Replace('#', '\\').Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .All(token => text.Contains(token, StringComparison.OrdinalIgnoreCase));
    }
}
