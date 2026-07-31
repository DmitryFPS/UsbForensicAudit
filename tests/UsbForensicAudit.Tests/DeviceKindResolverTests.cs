using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceKindResolverTests
{
    [Fact]
    public void Phone_stays_a_phone_regardless_of_how_it_is_attached()
    {
        var overUsb = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_Xiaomi#2412&0",
            Transport = "MTP/PTP/WPD"
        };
        var overBluetooth = new UsbDeviceRecord
        {
            DeviceInstanceId = @"BTHENUM\{0000111e-0000-1000-8000-00805f9b34fb}_LOCALMFG&0000\7&2a1b",
            ClassGuid = "{c06ff265-ae09-48f0-812c-16753d7cba83}"
        };

        Assert.Equal(DeviceKindResolver.PortableDevice, DeviceKindResolver.Resolve(overUsb));
        Assert.Equal(DeviceKindResolver.PortableDevice, DeviceKindResolver.Resolve(overBluetooth));
    }

    [Fact]
    public void Storage_is_recognised_by_its_service_not_by_the_bus_name()
    {
        var record = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SCSI\Disk&Ven_&Prod_General_UDisk\5&2a1b&0",
            Service = "uaspstor"
        };

        Assert.Equal(DeviceKindResolver.Storage, DeviceKindResolver.Resolve(record));
    }

    [Fact]
    public void Hub_and_composite_interface_are_infrastructure_not_devices()
    {
        Assert.Equal(DeviceKindResolver.Infrastructure,
            DeviceKindResolver.Resolve(new UsbDeviceRecord { Classification = "Hub" }));
        Assert.Equal(DeviceKindResolver.Infrastructure,
            DeviceKindResolver.Resolve(new UsbDeviceRecord { Classification = "Composite" }));
    }

    [Fact]
    public void Registry_only_records_are_not_presented_as_devices()
    {
        Assert.Equal(DeviceKindResolver.RegistryTrace,
            DeviceKindResolver.Resolve(new UsbDeviceRecord { DeviceType = "USBFlags" }));
        Assert.Equal(DeviceKindResolver.RegistryTrace,
            DeviceKindResolver.Resolve(new UsbDeviceRecord { DeviceType = "VolumeMapping" }));
    }

    [Fact]
    public void Kind_and_transport_are_two_separate_answers()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412&0",
            Service = "disk",
            Transport = "MSC/USBSTOR",
            Connection = "USB",
            Classification = "External",
            ClassificationConfidence = "High"
        };
        device.DeviceKind = DeviceKindResolver.Resolve(device);

        Assert.Equal("Носитель информации", device.DeviceKindText);
        Assert.Equal("По USB как обычный диск", device.TransportDisplayText);
        Assert.Equal("Внешнее, принесённое устройство", device.OriginDisplayText);
        Assert.DoesNotContain("USBSTOR", device.ClassificationDisplayText, StringComparison.Ordinal);
        Assert.Contains("transport=MSC/USBSTOR", device.ClassificationCodesText, StringComparison.Ordinal);
    }

    [Fact]
    public void Classifier_fills_the_kind_for_every_record()
    {
        var devices = new List<UsbDeviceRecord>
        {
            new() { DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk\2412&0", Service = "disk" },
            new() { DeviceInstanceId = @"USB\VID_2717&PID_FF40\8dde262e" },
            new() { DeviceInstanceId = @"USB\ROOT_HUB30\4&1f2e", Service = "usbhub3" }
        };

        DeviceTransportClassifier.ClassifyAll(devices);

        Assert.Equal(DeviceKindResolver.Storage, devices[0].DeviceKind);
        Assert.Equal(DeviceKindResolver.Infrastructure, devices[2].DeviceKind);
        Assert.All(devices, x => Assert.False(string.IsNullOrWhiteSpace(x.DeviceKind)));
    }
}
