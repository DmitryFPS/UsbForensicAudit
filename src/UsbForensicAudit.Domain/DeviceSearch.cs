namespace UsbForensicAudit;

public static class DeviceSearch
{
    public static bool Matches(UsbDeviceRecord device, string? query)
    {
        var text = string.Join(" ", device.DisplayName, device.DeviceInstanceId, device.Vid, device.Pid,
            device.Serial, device.Manufacturer, device.Product, device.Source, device.CategoryText,
            string.Join(" ", device.IdentityAliases));
        return (query ?? "").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .All(token => text.Contains(token, StringComparison.OrdinalIgnoreCase));
    }
}
