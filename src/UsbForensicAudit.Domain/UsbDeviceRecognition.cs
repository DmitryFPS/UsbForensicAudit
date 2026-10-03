using System.Text.RegularExpressions;

namespace UsbForensicAudit;

/// <summary>Read-only catalogue hints. Never change evidence, identity or grouping.</summary>
public static class UsbDeviceRecognition
{
    public static UsbVendorLookup Lookup(UsbDeviceRecord record)
    {
        // Bluetooth vendor identifiers can belong to a different numbering authority.
        if (record.DeviceInstanceId.StartsWith("BTH", StringComparison.OrdinalIgnoreCase)) { return new(); }
        var candidates = new[] { record.DeviceInstanceId, record.HardwareIds }
            .Concat(record.IdentityAliases)
            .SelectMany(x => x.Split(['\0', '\r', '\n', ';', '|', ','], StringSplitOptions.RemoveEmptyEntries))
            .Select(x => DeviceIdentifierMetadata.Pair(x.Trim()))
            .Where(x => x.HasValue).Select(x => x!.Value).Distinct().ToArray();
        var vid = record.Vid.Trim().ToUpperInvariant();
        var pid = record.Pid.Trim().ToUpperInvariant();
        if (candidates.Length > 1) { return new(); }
        if (candidates.Length == 1)
        {
            var pair = candidates[0];
            if ((vid.Length > 0 && vid != pair.Vid) || (pid.Length > 0 && pid != pair.Pid)) { return new(); }
            vid = pair.Vid;
            pid = pair.Pid;
        }
        if (!Regex.IsMatch(vid, "^[0-9A-F]{4}$") || (pid.Length > 0 && !Regex.IsMatch(pid, "^[0-9A-F]{4}$"))) { return new(); }
        return UsbVendorDatabase.Lookup(vid, pid);
    }

    public static string DisplayName(UsbDeviceRecord record)
    {
        var friendly = IndirectString.Resolve(record.FriendlyName);
        var product = IndirectString.Resolve(record.Product);
        if (DeviceNameQuality.IsClassName(friendly) && !DeviceNameQuality.IsClassName(product)) { return product; }
        var lookup = Lookup(record);
        return NeedsModel(record) && lookup.HasProduct
            ? $"{lookup.DeviceDescription} (по VID/PID)"
            : record.OwnDisplayName;
    }

    public static string Model(UsbDeviceRecord record)
    {
        var friendly = IndirectString.Resolve(record.FriendlyName);
        if (DeviceNameQuality.IsClassName(IndirectString.Resolve(record.Product)) && !DeviceNameQuality.IsClassName(friendly)) { return friendly; }
        var lookup = Lookup(record);
        return NeedsModel(record) && lookup.HasProduct
            ? $"{lookup.ProductName} (по VID/PID)"
            : UserDisplayText.ModelName(record.Product, record.FriendlyName, record.Revision, record.Pid);
    }

    public static string Manufacturer(UsbDeviceRecord record)
    {
        var vendor = IndirectString.Resolve(record.Manufacturer);
        var lookup = Lookup(record);
        return string.IsNullOrWhiteSpace(vendor) && lookup.HasVendor
            ? $"{lookup.VendorName} (по VID)"
            : UserDisplayText.ManufacturerName(record.Manufacturer, record.FriendlyName, record.Vid);
    }

    public static string Evidence(UsbDeviceRecord record)
    {
        var lookup = Lookup(record);
        if (!lookup.HasVendor) { return "Однозначное совпадение в USB-справочнике не найдено."; }
        var codes = lookup.HasProduct ? $"VID {lookup.Vid} / PID {lookup.Pid}" : $"VID {lookup.Vid}";
        return $"USB-справочник: {codes} → {lookup.DeviceDescription}. Справочное соответствие; не подтверждает конкретный экземпляр или подлинность устройства.";
    }

    private static bool NeedsModel(UsbDeviceRecord record) =>
        DeviceNameQuality.IsClassName(IndirectString.Resolve(record.FriendlyName))
        && DeviceNameQuality.IsClassName(IndirectString.Resolve(record.Product));
}
