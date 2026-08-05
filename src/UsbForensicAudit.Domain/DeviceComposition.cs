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
    /// Запись, которую список по умолчанию не показывает. Скрывается ровно то,
    /// что уже видно в другом месте: неглавные записи своего устройства, части
    /// самой машины — концентраторы, контроллеры, служебные узлы шины — и метки
    /// томов MountedDevices, не указывающие на съёмный носитель.
    /// </summary>
    public static bool IsFoldedByDefault(UsbDeviceRecord device) =>
        (!device.IsCanonicalPrimary && !string.IsNullOrWhiteSpace(device.CanonicalDeviceId))
        || device.Externality == DeviceExternality.BusInfrastructure
        || IsInternalVolumeMapping(device);

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
