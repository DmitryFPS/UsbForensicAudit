namespace UsbForensicAudit;

/// <summary>
/// Что за устройство — отдельно от того, как оно подключено. Раньше эти два
/// вопроса отвечались одной строкой, из-за чего в графе «тип устройства»
/// оказывались то шина (USBSTOR), то протокол (MTP), то вовсе название
/// раздела реестра, откуда пришла запись. Для читателя отчёта это разные
/// вопросы: телефон остаётся телефоном и по USB, и по Bluetooth.
/// </summary>
public static class DeviceKindResolver
{
    public const string Storage = "Storage";
    public const string PortableDevice = "PortableDevice";
    public const string Camera = "Camera";
    public const string Input = "Input";
    public const string Printer = "Printer";
    public const string Audio = "Audio";
    public const string Network = "Network";
    public const string SerialPort = "SerialPort";
    public const string Infrastructure = "Infrastructure";
    public const string RegistryTrace = "RegistryTrace";
    public const string Unknown = "Unknown";

    private static readonly Dictionary<string, string> ClassGuidKinds = new(StringComparer.OrdinalIgnoreCase)
    {
        ["{4d36e967-e325-11ce-bfc1-08002be10318}"] = Storage,
        ["{71a27cdd-812a-11d0-bec7-08002be2092f}"] = Storage,
        ["{4d36e97b-e325-11ce-bfc1-08002be10318}"] = Storage,
        ["{c06ff265-ae09-48f0-812c-16753d7cba83}"] = PortableDevice,
        ["{6bdd1fc6-810f-11d0-bec7-08002be2092f}"] = Camera,
        ["{4d36e96f-e325-11ce-bfc1-08002be10318}"] = Input,
        ["{4d36e96b-e325-11ce-bfc1-08002be10318}"] = Input,
        ["{745a17a0-74d3-11d0-b6fe-00a0c90f57da}"] = Input,
        ["{4d36e979-e325-11ce-bfc1-08002be10318}"] = Printer,
        ["{4d36e96c-e325-11ce-bfc1-08002be10318}"] = Audio,
        ["{c166523c-fe0c-4a94-a586-f1a80cfbbf3e}"] = Audio,
        ["{4d36e972-e325-11ce-bfc1-08002be10318}"] = Network,
        ["{4d36e978-e325-11ce-bfc1-08002be10318}"] = SerialPort,
        ["{36fc9e60-c465-11cf-8056-444553540000}"] = Infrastructure,
        ["{88bae032-5a81-49f0-bc3d-a4ff138216d6}"] = Infrastructure
    };

    private static readonly Dictionary<string, string> ServiceKinds = new(StringComparer.OrdinalIgnoreCase)
    {
        ["disk"] = Storage,
        ["uaspstor"] = Storage,
        ["usbstor"] = Storage,
        ["sdstor"] = Storage,
        ["wpdbusenumroot"] = PortableDevice,
        ["wudfwpdmtp"] = PortableDevice,
        ["wudfwpdfs"] = PortableDevice,
        ["wudfwpdmtpprintclass"] = Printer,
        ["usbprint"] = Printer,
        ["kbdhid"] = Input,
        ["mouhid"] = Input,
        ["hidusb"] = Input,
        ["usbhid"] = Input,
        ["usbaudio"] = Audio,
        ["usbaudio2"] = Audio,
        ["usbccgp"] = Infrastructure,
        ["usbhub"] = Infrastructure,
        ["usbhub3"] = Infrastructure,
        ["usbxhci"] = Infrastructure,
        ["usbser"] = SerialPort,
        ["usbncm"] = Network,
        ["rndismp6"] = Network
    };

    public static string Resolve(UsbDeviceRecord device)
    {
        if (device.DeviceType.Equals("VolumeMapping", StringComparison.OrdinalIgnoreCase)
            || device.DeviceType.Equals("USBFlags", StringComparison.OrdinalIgnoreCase)
            || device.DeviceType.Equals("VolumeHistory", StringComparison.OrdinalIgnoreCase)
            || device.DeviceType.Equals("VolumeLabel", StringComparison.OrdinalIgnoreCase)
            || device.VisualCategory.Equals("UsbFlagsTrace", StringComparison.OrdinalIgnoreCase))
        {
            return RegistryTrace;
        }

        // Запись интерфейса — след появления устройства, а не само устройство,
        // если её не удалось приклеить к физической записи.
        if (device.DeviceType.Equals("DeviceInterface", StringComparison.OrdinalIgnoreCase)
            && device.Transport == "Unknown")
        {
            return RegistryTrace;
        }

        if (device.Classification is "Hub" or "Composite")
        {
            return Infrastructure;
        }

        if (ServiceKinds.TryGetValue(device.Service.Trim(), out var byService))
        {
            return byService;
        }

        if (ClassGuidKinds.TryGetValue(device.ClassGuid.Trim(), out var byClass))
        {
            return byClass;
        }

        var id = device.DeviceInstanceId;
        if (id.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith(@"SD\", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith(@"SDBUS\", StringComparison.OrdinalIgnoreCase))
        {
            return Storage;
        }

        if (id.StartsWith(@"SWD\WPDBUSENUM\", StringComparison.OrdinalIgnoreCase)
            || device.Transport == "MTP/PTP/WPD")
        {
            return PortableDevice;
        }

        if (id.StartsWith(@"USBPRINT\", StringComparison.OrdinalIgnoreCase))
        {
            return Printer;
        }

        if (id.StartsWith(@"USBSER\", StringComparison.OrdinalIgnoreCase))
        {
            return SerialPort;
        }

        if (id.StartsWith(@"HID\", StringComparison.OrdinalIgnoreCase))
        {
            return Input;
        }

        if (device.Transport is "MSC/USBSTOR" or "UASP/SCSI" or "Internal Disk" or "Internal NVMe" or "Virtual Disk")
        {
            return Storage;
        }

        return Unknown;
    }

    public static string Describe(string? kind) => kind switch
    {
        Storage => "Носитель информации",
        PortableDevice => "Телефон или другое портативное устройство",
        Camera => "Камера или сканер",
        Input => "Клавиатура, мышь или похожее устройство ввода",
        Printer => "Принтер",
        Audio => "Звуковое устройство",
        Network => "Сетевой адаптер",
        SerialPort => "Последовательный порт",
        Infrastructure => "Часть самой шины: разветвитель, контроллер или интерфейс составного устройства",
        RegistryTrace => "Не устройство, а след в реестре",
        _ => "Назначение устройства определить не удалось"
    };

    /// <summary>
    /// Как устройство подключалось. Отвечает на вопрос «каким путём данные шли
    /// в машину», а не «что это было».
    /// </summary>
    public static string DescribeTransport(string? transport, string? connection) => transport switch
    {
        "MSC/USBSTOR" => "По USB как обычный диск",
        "UASP/SCSI" => "По USB в скоростном режиме UASP",
        "MTP/PTP/WPD" => "По USB в режиме передачи файлов (MTP/PTP), как телефон или камера",
        "USB" => "По USB",
        "USB4/Thunderbolt/PCIe-tunneled candidate" => "По USB4 или Thunderbolt",
        "Internal NVMe" => "Внутренняя шина NVMe",
        "Internal Disk" => "Внутренняя дисковая шина",
        "Virtual Disk" => "Виртуальный диск гипервизора",
        _ => connection switch
        {
            "USB" => "По USB",
            "USB4/Thunderbolt" => "По USB4 или Thunderbolt",
            "PCIe-tunneled candidate" => "Возможно, через туннель PCIe (USB4/Thunderbolt)",
            _ => "Способ подключения определить не удалось"
        }
    };

    /// <summary>
    /// Внешнее устройство или часть самой машины.
    /// </summary>
    public static string DescribeOrigin(string? classification) => classification switch
    {
        "External" => "Внешнее, принесённое устройство",
        "BuiltIn" => "Встроенное в машину",
        "Hub" => "Часть шины, а не отдельное устройство",
        "Composite" => "Интерфейс составного устройства",
        "Virtual" => "Виртуальное, создано программой",
        _ => "Происхождение определить не удалось"
    };

    public static string DescribeConfidence(string? confidence) => confidence switch
    {
        "High" => "надёжно",
        "Medium" => "с оговорками",
        "Low" => "предположительно",
        _ => "без подтверждения"
    };
}
