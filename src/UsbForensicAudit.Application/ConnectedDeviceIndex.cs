namespace UsbForensicAudit;

/// <summary>
/// Индекс полных PnP-идентификаторов подключённых экземпляров. Совпадение модели,
/// серийного фрагмента или старой буквы диска не подтверждает живое подключение.
/// </summary>
public sealed class ConnectedDeviceIndex
{
    private readonly HashSet<string> _identifiers;
    private readonly HashSet<string> _unknown;
    public bool IsComplete { get; }
    public string Error { get; }

    private ConnectedDeviceIndex(IEnumerable<string?> identifiers, bool complete = false,
        IEnumerable<string?>? unknown = null, string error = "")
    {
        _identifiers = Normalize(identifiers);
        _unknown = Normalize(unknown ?? []);
        IsComplete = complete;
        Error = error;
    }

    private static HashSet<string> Normalize(IEnumerable<string?> ids) => ids.Select(DeviceLiveMatcher.NormalizePnpId)
        .Where(x => x.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);

    public static ConnectedDeviceIndex Empty { get; } = new([]);

    // Буквы дисков оставлены в контракте проб, но не доказывают подключение устройства.
    public static ConnectedDeviceIndex Build(IEnumerable<string?> pnpIdentifiers, IEnumerable<string?> driveLetters) =>
        new(pnpIdentifiers, complete: true);

    public static ConnectedDeviceIndex FromSnapshot(IEnumerable<string?> connected, IEnumerable<string?> unknown,
        bool complete, string error = "") => new(connected, complete, unknown, error);

    public bool IsConnected(UsbDeviceRecord device) => GetConnectionState(device) == true;

    public bool? GetConnectionState(UsbDeviceRecord device)
    {
        var ids = new[] { device.DeviceInstanceId }.Concat(device.IdentityAliases).Concat(device.LinkedSourceIds)
            .Select(DeviceLiveMatcher.NormalizePnpId).ToArray();
        if (device.Connection == "Bluetooth" || BluetoothEnumeratorId.DeviceAddress(device.DeviceInstanceId).Length > 0)
        {
            ids = ids.Where(id => BluetoothEnumeratorId.DeviceAddress(id).Length > 0).ToArray();
        }
        else if (device.Connection == "USB")
        {
            ids = ids.Where(id => BluetoothEnumeratorId.DeviceAddress(id).Length == 0).ToArray();
        }
        if (ids.Any(_identifiers.Contains)) { return true; }
        if (ids.Any(_unknown.Contains)) { return null; }
        if (IsComplete) { return false; }
        // An unavailable probe cannot refute a positive observation made by the live merger.
        return device.IsCurrentlyConnected ? true : null;
    }
}
