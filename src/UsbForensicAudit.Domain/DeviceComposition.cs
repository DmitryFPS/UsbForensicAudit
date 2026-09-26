namespace UsbForensicAudit;

/// <summary>
/// Одно физическое устройство Windows описывает несколькими записями. У телефона
/// по Bluetooth это полтора десятка услуг, у веб-камеры — видеопоток и микрофон,
/// у флешки — запись шины, запись накопителя и узел переносимого устройства.
///
/// Каждая такая запись — доказательство и должна сохраниться, но в списке
/// устройств им не место: читатель ищет там вещи, а не строки реестра. Список
/// показывает главную запись, а остальные складываются в неё.
/// </summary>
public static class DeviceComposition
{
    /// <summary>
    /// Запись описывает часть другой записи, а не отдельную вещь: услугу
    /// сопряжённого устройства Bluetooth или грань составного устройства USB.
    /// </summary>
    public static bool IsPartOfAnotherDevice(UsbDeviceRecord device) =>
        BluetoothEnumeratorId.IsServiceRecord(device.DeviceInstanceId)
        || device.DeviceInstanceId.Contains("&MI_", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// В обычном списке остаются устройства и самостоятельные следы устройств.
    /// Служебные записи томов (включая USB-тома), внутренние диски и части шины
    /// доступны в режиме всех записей. Сведения о томах сохраняются в досье.
    /// </summary>
    public static bool IsFoldedByDefault(UsbDeviceRecord device) =>
        (!device.IsCanonicalPrimary && !string.IsNullOrWhiteSpace(device.CanonicalDeviceId))
        || device.Externality == DeviceExternality.BusInfrastructure
        || IsVolumeMetadata(device)
        || device.Transport is "Internal NVMe" or "Internal Disk";

    public static bool IsVolumeMetadata(UsbDeviceRecord device) =>
        device.DeviceType.Equals("VolumeMapping", StringComparison.OrdinalIgnoreCase)
        || device.DeviceType.Equals("VolumeLabel", StringComparison.OrdinalIgnoreCase)
        || IsWpdVolume(device);

    /// <summary>WPD может описывать обычный локальный том, а не USB-телефон.</summary>
    public static bool IsWpdVolume(UsbDeviceRecord device)
    {
        const string prefix = @"SWD\WPDBUSENUM\";
        return device.DeviceInstanceId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
               && Guid.TryParse(device.DeviceInstanceId[prefix.Length..].Split('\\')[0], out _);
    }

    /// <summary>Обёртка WPD вокруг USBSTOR не меняет накопитель в MTP-телефон.</summary>
    public static bool IsWpdUsbStorage(UsbDeviceRecord device) =>
        device.DeviceInstanceId.StartsWith(@"SWD\WPDBUSENUM\", StringComparison.OrdinalIgnoreCase)
        && (device.DeviceInstanceId.Contains(@"USBSTOR\", StringComparison.OrdinalIgnoreCase)
            || device.DeviceInstanceId.Contains("USBSTOR#", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Служебная метка тома из MountedDevices, за которой не стоит съёмный
    /// носитель: Volume GUID или буква внутреннего диска. Для аудита USB это
    /// внутренняя бухгалтерия Windows — по умолчанию она скрыта. Метки,
    /// указывающие на съёмный USB-носитель, остаются в списке: они привязывают
    /// букву диска к конкретной флешке, что важно для доказательств.
    /// </summary>
    public static bool IsInternalVolumeMapping(UsbDeviceRecord device) =>
        device.DeviceType == "VolumeMapping"
        && !device.Volumes.Any(v =>
            v.DevicePath.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
            || v.DevicePath.Contains("RemovableMedia", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Записи, свёрнутые в эту. Порядок — от услуг и граней устройства к прочим
    /// записям: сначала то, что говорит о возможностях устройства.
    /// </summary>
    public static IReadOnlyList<UsbDeviceRecord> PartsOf(
        UsbDeviceRecord device, IEnumerable<UsbDeviceRecord> all)
    {
        if (string.IsNullOrWhiteSpace(device.CanonicalDeviceId))
        {
            return [];
        }

        return all
            .Where(x => !ReferenceEquals(x, device))
            .Where(x => x.CanonicalDeviceId.Equals(device.CanonicalDeviceId, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(IsPartOfAnotherDevice)
            .ThenBy(x => x.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Чем эта запись обернулась в списке — словами для окна сведений. Пустая
    /// строка означает, что складывать было нечего.
    /// </summary>
    public static string Describe(UsbDeviceRecord device, IEnumerable<UsbDeviceRecord> all)
    {
        var parts = PartsOf(device, all);
        if (parts.Count == 0)
        {
            return "";
        }

        var lines = parts.Select(part =>
        {
            var meaning = string.IsNullOrWhiteSpace(part.UserMeaning) ? part.CategoryText : part.UserMeaning;
            return $"• {part.DisplayName} — {meaning}{Environment.NewLine}   {part.DeviceInstanceId}";
        });

        return $"{Count(parts.Count)} этого же устройства:{Environment.NewLine}"
               + string.Join(Environment.NewLine, lines);
    }

    private static string Count(int value) => value switch
    {
        1 => "Ещё одна запись Windows",
        _ => $"Ещё {value} записей Windows"
    };
}
