namespace UsbForensicAudit;

/// <summary>
/// GUID, которые встречаются в путях устройств, но не опознают конкретный экземпляр:
/// классы интерфейсов, классы установки и заглушка контейнера. Если такой GUID
/// принять за серийный номер, все устройства одного класса сливаются в одно.
/// </summary>
public static class WellKnownDeviceGuids
{
    private static readonly HashSet<string> NonIdentifying = new(StringComparer.OrdinalIgnoreCase)
    {
        // Контейнер отсутствует.
        "00000000-0000-0000-0000-000000000000",
        "00000000-0000-0000-FFFF-FFFFFFFFFFFF",

        // Классы интерфейсов устройств.
        "53F56307-B6BF-11D0-94F2-00A0C91EFB8B", // GUID_DEVINTERFACE_DISK
        "53F56308-B6BF-11D0-94F2-00A0C91EFB8B", // GUID_DEVINTERFACE_TAPE
        "53F5630A-B6BF-11D0-94F2-00A0C91EFB8B", // GUID_DEVINTERFACE_PARTITION
        "53F5630B-B6BF-11D0-94F2-00A0C91EFB8B", // GUID_DEVINTERFACE_WRITEONCEDISK
        "53F5630C-B6BF-11D0-94F2-00A0C91EFB8B", // GUID_DEVINTERFACE_VOLUME
        "53F5630D-B6BF-11D0-94F2-00A0C91EFB8B", // GUID_DEVINTERFACE_MEDIUMCHANGER
        "53F56311-B6BF-11D0-94F2-00A0C91EFB8B", // GUID_DEVINTERFACE_STORAGEPORT
        "A5DCBF10-6530-11D2-901F-00C04FB951ED", // GUID_DEVINTERFACE_USB_DEVICE
        "F18A0E88-C30C-11D0-8815-00A0C906BED8", // GUID_DEVINTERFACE_USB_HUB
        "3ABF6F2D-71C4-462A-8A92-1E6861E6AF27", // GUID_DEVINTERFACE_USB_HOST_CONTROLLER
        "6AC27878-A6FA-4155-BA85-F98F491D4F33", // GUID_DEVINTERFACE_WPD
        "BA0C718F-4DED-49B7-BDD3-FABE28661211", // GUID_DEVINTERFACE_WPD_PRIVATE
        "0AF2F2EC-8232-4E7B-AF6A-15C6EF7A5D14", // WPD service
        "10497B1B-BA51-44E5-8318-A65C837B6661", // GUID_DEVINTERFACE_SERVICE

        // Классы установки, встречающиеся в ClassGUID.
        "4D36E967-E325-11CE-BFC1-08002BE10318", // DiskDrive
        "4D36E96F-E325-11CE-BFC1-08002BE10318", // Mouse
        "36FC9E60-C465-11CF-8056-444553540000", // USB
        "EEC5AD98-8080-425F-922A-DABF3DE3F69A"  // WPD
    };

    public static bool IsNonIdentifying(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        return Guid.TryParse(value.Trim().Trim('{', '}'), out var parsed)
               && NonIdentifying.Contains(parsed.ToString("D"));
    }

    /// <summary>
    /// Значение целиком является GUID: как идентификатор экземпляра оно годится
    /// только там, где GUID осмыслен — например в ContainerID.
    /// </summary>
    public static bool IsBareGuid(string? value) =>
        !string.IsNullOrWhiteSpace(value) && Guid.TryParse(value.Trim().Trim('{', '}'), out _);
}
