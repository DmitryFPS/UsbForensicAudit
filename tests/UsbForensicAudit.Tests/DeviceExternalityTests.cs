using System.Linq;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Во вкладке «USB устройства» цвет отвечает на вопрос «приносили ли устройство
/// с собой». Тесты закрепляют разделение: носитель и телефон отделены от
/// корневых концентраторов, а там, где следов не хватает, программа говорит
/// «не подтверждено», а не выдаёт догадку за вывод.
/// </summary>
public class DeviceExternalityTests
{
    [Fact]
    public void Flash_drive_is_external_media()
    {
        var device = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer\4C530001120523118563&0",
            Service = "disk",
            HardwareIds = @"USBSTOR\DiskSanDisk_Cruzer"
        });

        Assert.Equal(DeviceExternality.ExternalMedia, device.Externality);
        Assert.True(device.IsExternalDevice);
    }

    [Fact]
    public void Phone_over_mtp_is_external_media()
    {
        var device = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_Samsung#0123456789ABCDEF&0",
            Service = "WUDFWpdMtp"
        });

        Assert.Equal(DeviceExternality.ExternalMedia, device.Externality);
    }

    [Fact]
    public void Bluetooth_pair_is_external_peripheral()
    {
        var device = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"BTHENUM\Dev_887598C2F5F2\7&1a2b3c4d&0&BluetoothDevice_887598C2F5F2",
            FriendlyName = "Гарнитура"
        });

        Assert.Equal(DeviceExternality.ExternalPeripheral, device.Externality);
        Assert.True(device.IsExternalDevice);
    }

    /// <summary>
    /// Услуга сопряжённого устройства живёт на той же шине, но принесённой
    /// вещью не является: у одной гарнитуры таких записей около десятка.
    /// </summary>
    [Fact]
    public void Bluetooth_service_of_that_pair_is_not_a_device_of_its_own()
    {
        var device = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"BTHENUM\{0000111e-0000-1000-8000-00805f9b34fb}_LOCALMFG&0000\7&1a2b3c4d&0"
        });

        Assert.Equal(DeviceExternality.BusInfrastructure, device.Externality);
        Assert.False(device.IsExternalDevice);
    }

    [Fact]
    public void Root_hub_is_bus_infrastructure_not_external()
    {
        var device = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\ROOT_HUB30\4&1a2b3c4d&0&0",
            Service = "USBHUB3",
            FriendlyName = "Корневой USB-концентратор (USB 3.0)"
        });

        Assert.Equal(DeviceExternality.BusInfrastructure, device.Externality);
        Assert.False(device.IsExternalDevice);
    }

    /// <summary>
    /// Контроллер Thunderbolt распаян на материнской плате. Через него внешние
    /// устройства подключают, но принесённой вещью он от этого не становится.
    /// </summary>
    [Fact]
    public void Thunderbolt_controller_of_the_machine_is_not_a_brought_device()
    {
        var device = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"PCI\VEN_8086&DEV_7EC2&SUBSYS_3D6C17AA&REV_10\3&11583659&0&6A",
            Service = "nhi",
            FriendlyName = "Thunderbolt(TM) Controller - 7EC2"
        });

        Assert.Equal(DeviceExternality.BusInfrastructure, device.Externality);
        Assert.False(device.IsExternalDevice);
    }

    [Fact]
    public void Composite_interface_is_not_counted_as_separate_external_device()
    {
        var device = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_046D&PID_C52B&MI_00\6&1a2b3c4d&0&0000",
            Service = "HidUsb"
        });

        Assert.Equal(DeviceExternality.BusInfrastructure, device.Externality);
    }

    [Fact]
    public void Internal_nvme_disk_is_built_in()
    {
        var device = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"SCSI\Disk&Ven_NVMe&Prod_Samsung_SSD_980\5&1a2b3c4d&0&000000",
            Service = "disk",
            HardwareIds = @"SCSI\DiskNVMe____Samsung_SSD_980 GENDISK"
        });

        Assert.Equal(DeviceExternality.BuiltInDevice, device.Externality);
        Assert.False(device.IsExternalDevice);
    }

    [Fact]
    public void Usbflags_residue_stays_a_registry_trace()
    {
        var device = new UsbDeviceRecord
        {
            DeviceType = "USBFlags",
            VisualCategory = "UsbFlagsTrace",
            DeviceInstanceId = "USBFLAGS\\090C1000"
        };
        DeviceTransportClassifier.Classify(device);

        Assert.Equal(DeviceExternality.RegistryTrace, device.Externality);
        Assert.False(device.IsExternalDevice);
    }

    /// <summary>
    /// Клавиатуру ноутбука Windows описывает так же, как внешнюю: обе висят на
    /// шине USB. Придумывать вывод здесь нельзя — это прямо сказано читателю.
    /// </summary>
    [Fact]
    public void Plain_usb_device_without_evidence_is_reported_as_undecided()
    {
        var device = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_048D&PID_C197\5&1a2b3c4d&0&4",
            Service = "HidUsb"
        });

        Assert.Equal(DeviceExternality.PossiblyExternal, device.Externality);
        Assert.False(device.IsExternalDevice);
        Assert.Contains("не подтверждено", device.ExternalityText);
    }

    [Fact]
    public void Devices_are_ordered_with_brought_in_ones_on_top()
    {
        var trace = new UsbDeviceRecord { DeviceType = "USBFlags", VisualCategory = "UsbFlagsTrace" };
        var media = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_Kingston\0123&0",
            Service = "disk"
        });
        var hub = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\ROOT_HUB30\4&1&0",
            Service = "USBHUB3"
        });
        DeviceTransportClassifier.Classify(trace);

        var ordered = MainViewModel.OrderDevices([trace, hub, media]).ToArray();

        Assert.Same(media, ordered[0]);
        Assert.Same(hub, ordered[1]);
        Assert.Same(trace, ordered[2]);
    }

    [Fact]
    public void Summary_counts_brought_in_devices()
    {
        var media = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_Kingston\0123&0",
            Service = "disk"
        });
        var hub = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\ROOT_HUB30\4&1&0",
            Service = "USBHUB3"
        });

        var summary = MainViewModel.DescribeExternalDevices([media, hub]);

        Assert.Contains("Принесённых устройств: 1", summary);
        // Корневой концентратор — часть машины: в таблице его нет, но и потерян
        // он не был, о чём сводка говорит прямо.
        Assert.Contains("Строк в таблице: 1", summary);
        Assert.Contains("Свёрнуто в них записей реестра: 1", summary);
    }

    private static UsbDeviceRecord Classified(UsbDeviceRecord device)
    {
        DeviceTransportClassifier.Classify(device);
        return device;
    }
}
