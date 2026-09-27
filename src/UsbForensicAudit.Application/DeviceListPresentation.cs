namespace UsbForensicAudit;

/// <summary>Фильтрует устройства целиком, сохраняя их связанные записи в раскрываемой группе.</summary>
public static class DeviceListPresentation
{
    public static object GroupKey(UsbDeviceRecord device)
    {
        if (!string.IsNullOrWhiteSpace(device.CanonicalDeviceId))
        {
            return "GROUP:" + device.CanonicalDeviceId.Trim().ToUpperInvariant();
        }
        var id = DevicePathNormalizer.CanonicalDeviceId(device.DeviceInstanceId, replaceHashes: true);
        return id.Length > 0 ? "INSTANCE:" + id : device;
    }

    public static HashSet<UsbDeviceRecord> Select(IEnumerable<UsbDeviceRecord> records,
        bool includeTechnical, string? query, string category = "All")
    {
        return records.GroupBy(GroupKey)
            .Where(group => includeTechnical || group.Any(x => !DeviceComposition.IsFoldedByDefault(x)))
            .Where(group => group.Any(x => MatchesCategory(x, category)))
            .Where(group => DeviceSearch.Matches(group, query))
            .SelectMany(group => group).ToHashSet();
    }

    private static bool MatchesCategory(UsbDeviceRecord device, string category) => category switch
    {
        "All" => true,
        "ExternalOnly" => device.IsExternalDevice,
        "ExternalMedia" => device.Externality == DeviceExternality.ExternalMedia,
        _ => device.Classification.Equals(category, StringComparison.OrdinalIgnoreCase)
             || device.Transport.Equals(category, StringComparison.OrdinalIgnoreCase)
             || device.Connection.Equals(category, StringComparison.OrdinalIgnoreCase)
    };
}
