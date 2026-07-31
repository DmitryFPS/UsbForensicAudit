namespace UsbForensicAudit;

/// <summary>
/// Отвечает на вопрос, который на самом деле задаёт читатель отчёта: приносили
/// ли устройство с собой. Прежний цвет строки показывал, из какого раздела
/// реестра пришла запись, и во вкладке одинаково зелёными были и флешка, и
/// корневой концентратор материнской платы.
///
/// Отдельно выделены устройства, которыми выносят данные (носители, телефоны,
/// камеры, карты памяти), и прочая внешняя периферия. Там, где по следам нельзя
/// отличить внешнее устройство от распаянного на внутренней шине — например у
/// клавиатуры ноутбука, — так и сказано, вместо догадки.
/// </summary>
public static class DeviceExternality
{
    public const string ExternalMedia = "ExternalMedia";
    public const string ExternalPeripheral = "ExternalPeripheral";
    public const string PossiblyExternal = "PossiblyExternal";
    public const string BuiltInDevice = "BuiltInDevice";
    public const string BusInfrastructure = "BusInfrastructure";
    public const string VirtualDevice = "VirtualDevice";
    public const string RegistryTrace = "RegistryTrace";
    public const string Undetermined = "Undetermined";

    /// <summary>
    /// Шины, на которых устройство физически не может быть распаяно внутри:
    /// носитель в кардридере, пара по Bluetooth, туннель USB4.
    /// </summary>
    private static readonly string[] AlwaysExternalPrefixes =
    [
        @"BTHENUM\", @"BTHLEDEVICE\", @"SD\", @"SDBUS\", @"USB4\"
    ];

    /// <summary>
    /// Чем выносят данные: носитель, телефон, камера. Для расследования это
    /// главная группа, и она должна быть видна с первого взгляда.
    /// </summary>
    private static readonly string[] DataCarryingKinds =
    [
        DeviceKindResolver.Storage, DeviceKindResolver.PortableDevice, DeviceKindResolver.Camera
    ];

    public static string Resolve(UsbDeviceRecord device)
    {
        if (device.DeviceKind == DeviceKindResolver.RegistryTrace
            || device.VisualCategory.Equals("UsbFlagsTrace", StringComparison.OrdinalIgnoreCase))
        {
            return RegistryTrace;
        }

        if (device.Classification == "Virtual")
        {
            return VirtualDevice;
        }

        if (device.Classification == "BuiltIn")
        {
            return BuiltInDevice;
        }

        // Интерфейс MI_xx — не отдельное устройство, а грань составного. Красить
        // его как внешнее значит удваивать в глазах читателя число устройств.
        if (device.Classification == "Composite")
        {
            return BusInfrastructure;
        }

        if (IsBusOwnInfrastructure(device))
        {
            return BusInfrastructure;
        }

        if (IsInternalBusTransport(device.Transport))
        {
            return BuiltInDevice;
        }

        if (DataCarryingKinds.Contains(device.DeviceKind))
        {
            return ExternalMedia;
        }

        if (StartsWithAny(device.DeviceInstanceId, AlwaysExternalPrefixes)
            || device.Transport is "MSC/USBSTOR" or "MTP/PTP/WPD" or "UASP/SCSI"
            || device.Connection is "USB4/Thunderbolt" or "PCIe-tunneled candidate")
        {
            return ExternalPeripheral;
        }

        // Классификатор помечает External любое устройство на шине USB — само
        // подключение по USB он считает признаком внешнего. Для клавиатуры
        // ноутбука это неверно, поэтому одной такой пометки мало: нужен либо
        // надёжный вывод классификатора, либо явный признак съёмности.
        if (device.Classification == "External"
            && (device.ClassificationConfidence == "High" || HasRemovableMarker(device)))
        {
            return ExternalPeripheral;
        }

        return device.Connection == "USB" || device.Transport == "USB" || device.Classification == "External"
            ? PossiblyExternal
            : Undetermined;
    }

    /// <summary>
    /// Windows помечает съёмностью то, что можно вынуть без выключения машины.
    /// Для распаянных внутри устройств этой пометки нет.
    /// </summary>
    private static bool HasRemovableMarker(UsbDeviceRecord device)
    {
        var text = $"{device.HardwareIds} {device.CompatibleIds} {device.FriendlyName} {device.Product}";
        return text.Contains("REMOVABLE", StringComparison.OrdinalIgnoreCase)
               || text.Contains("EXTERNAL", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsInternalBusTransport(string transport) =>
        transport is "Internal NVMe" or "Internal Disk";

    /// <summary>
    /// Корневой концентратор и хост-контроллер — часть самой машины, их видно по
    /// признакам. Обычный концентратор сюда не попадает: по следам в реестре
    /// нельзя отличить разветвитель, встроенный в ноутбук, от принесённого, и
    /// такая запись честнее выглядит как «возможно внешнее».
    /// </summary>
    private static bool IsBusOwnInfrastructure(UsbDeviceRecord device)
    {
        var text = $"{device.DeviceInstanceId} {device.Service} {device.FriendlyName} {device.HardwareIds}";
        return text.Contains("ROOT_HUB", StringComparison.OrdinalIgnoreCase)
               || text.Contains("HOST CONTROLLER", StringComparison.OrdinalIgnoreCase)
               || device.Service.Contains("USBXHCI", StringComparison.OrdinalIgnoreCase)
               || device.Service.Contains("USBEHCI", StringComparison.OrdinalIgnoreCase)
               || device.Service.StartsWith("Usb4", StringComparison.OrdinalIgnoreCase)
               || device.DeviceInstanceId.StartsWith(@"SWD\DRIVERENUM\", StringComparison.OrdinalIgnoreCase);
    }

    public static string Describe(string? externality) => externality switch
    {
        ExternalMedia => "Внешний носитель или телефон",
        ExternalPeripheral => "Внешнее устройство",
        PossiblyExternal => "Возможно внешнее — не подтверждено",
        BuiltInDevice => "Встроено в машину",
        BusInfrastructure => "Часть шины, а не отдельное устройство",
        VirtualDevice => "Виртуальное, создано программой",
        RegistryTrace => "След в реестре, самого устройства нет",
        _ => "Определить не удалось"
    };

    /// <summary>
    /// Устройство, которое кто-то принёс и подключил.
    /// </summary>
    public static bool IsExternal(string? externality) =>
        externality is ExternalMedia or ExternalPeripheral;

    /// <summary>
    /// Порядок вывода: сначала то, чем выносят данные, в конце — следы реестра.
    /// </summary>
    public static int Rank(string? externality) => externality switch
    {
        ExternalMedia => 0,
        ExternalPeripheral => 1,
        PossiblyExternal => 2,
        BuiltInDevice => 3,
        BusInfrastructure => 4,
        VirtualDevice => 5,
        RegistryTrace => 6,
        _ => 7
    };

    private static bool StartsWithAny(string value, string[] prefixes) =>
        prefixes.Any(prefix => value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
}
