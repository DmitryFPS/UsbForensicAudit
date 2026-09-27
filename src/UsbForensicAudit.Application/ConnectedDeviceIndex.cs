namespace UsbForensicAudit;

/// <summary>
/// Индекс полных PnP-идентификаторов подключённых экземпляров. Совпадение модели,
/// серийного фрагмента или старой буквы диска не подтверждает живое подключение.
/// </summary>
public sealed class ConnectedDeviceIndex
{
    private readonly HashSet<string> _identifiers;

    private ConnectedDeviceIndex(IEnumerable<string?> identifiers) =>
        _identifiers = identifiers.Select(DeviceLiveMatcher.NormalizePnpId)
            .Where(x => x.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);

    public static ConnectedDeviceIndex Empty { get; } = new([]);

    // Буквы дисков оставлены в контракте проб, но не доказывают подключение устройства.
    public static ConnectedDeviceIndex Build(IEnumerable<string?> pnpIdentifiers, IEnumerable<string?> driveLetters) =>
        new(pnpIdentifiers);

    public bool IsConnected(UsbDeviceRecord device) =>
        new[] { device.DeviceInstanceId }.Concat(device.IdentityAliases).Concat(device.LinkedSourceIds)
            .Select(DeviceLiveMatcher.NormalizePnpId).Any(_identifiers.Contains)
        || device.IsCurrentlyConnected;
}
