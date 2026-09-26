using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceOutputRegressionTests
{
    [Fact]
    public void Hiding_volume_rows_preserves_the_drive_letter_in_the_device_dossier()
    {
        const string id = @"USBSTOR\Disk&Ven_Test\SERIAL123&0";
        var device = new UsbDeviceRecord { DeviceInstanceId = id, Serial = "SERIAL123", VisualCategory = "RealUsb" };
        var mapping = new UsbDeviceRecord
        {
            DeviceType = "VolumeMapping",
            DeviceInstanceId = @"HKLM\SYSTEM\MountedDevices\DosDevices\F:",
            VisualCategory = "SupportArtifact",
            Volumes = [new() { DevicePath = id, DriveLetter = "F:", Source = "Registry: MountedDevices" }]
        };
        var result = new AuditResult { Devices = { device, mapping } };
        DeviceTransportClassifier.ClassifyAll(result.Devices);
        VolumeCorrelationService.Process(result);

        Assert.True(DeviceComposition.IsFoldedByDefault(mapping));
        Assert.False(DeviceComposition.IsFoldedByDefault(device));
        Assert.Contains(device.Volumes, x => x.DriveLetter == "F:" && x.DevicePath == id);
        Assert.Contains("F:", device.DriveLetters);
        Assert.Equal(2, result.Devices.Count);
    }

    [Theory]
    [InlineData("VolumeMapping")]
    [InlineData("VolumeLabel")]
    public void Usb_volume_metadata_is_kept_but_not_shown_as_an_extra_device(string type)
    {
        var record = new UsbDeviceRecord
        {
            DeviceType = type,
            VisualCategory = "SupportArtifact",
            IsCanonicalPrimary = true,
            Volumes = [new() { DevicePath = @"USBSTOR\Disk&Ven_Test\SERIAL123&0", DriveLetter = "F:" }]
        };

        Assert.True(DeviceComposition.IsFoldedByDefault(record));
        Assert.Equal("F:", Assert.Single(record.Volumes).DriveLetter);
        Assert.Equal(0, DeviceCountSummary.FromDevices([record]).PhysicalDevices);
    }

    [Theory]
    [InlineData(@"SWD\WPDBUSENUM\{33e43465-a87f-11f1-986a-9010576eda10}\0000000000100000")]
    [InlineData(@"swd\wpdbusenum\{33E43465-A87F-11F1-986A-9010576EDA10}\0000000000100000")]
    public void Wpd_volume_id_does_not_prove_an_external_phone(string id)
    {
        // В том числе уже сохранённая сессия со старой ошибочной классификацией.
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = id,
            DeviceType = "Portable/MTP",
            VisualCategory = "RealUsb",
            Transport = "MTP/PTP/WPD",
            Connection = "USB",
            Classification = "External",
            DeviceKind = DeviceKindResolver.PortableDevice
        };
        Assert.True(DeviceComposition.IsFoldedByDefault(device));
        Assert.False(device.IsExternalDevice);
        Assert.False(DeviceTransportClassifier.IsReportable(device));
        Assert.Equal(0, DeviceCountSummary.FromDevices([device]).PhysicalDevices);

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("Unknown", device.Connection);
        Assert.Equal("Unknown", device.Transport);
        Assert.Equal(DeviceKindResolver.RegistryTrace, device.DeviceKind);
    }

    [Theory]
    [InlineData(@"SWD\WPDBUSENUM\_??_USBSTOR\Disk&Ven_Test\SERIAL123&0")]
    [InlineData(@"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_Test#SERIAL123&0")]
    public void Wpd_wrapper_of_a_flash_drive_is_storage_not_a_phone(string id)
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = id,
            DeviceType = "Portable/MTP",
            Service = "WUDFWpdFs",
            ClassGuid = "{c06ff265-ae09-48f0-812c-16753d7cba83}"
        };
        DeviceTransportClassifier.Classify(device);

        Assert.Equal(DeviceKindResolver.Storage, device.DeviceKind);
        Assert.Equal("MSC/USBSTOR", device.Transport);
        Assert.Contains("USB-накопитель", device.CategoryText);
        Assert.False(DeviceComposition.IsFoldedByDefault(device));
        Assert.True(DeviceTransportClassifier.IsReportable(device));
    }

    [Fact]
    public void Genuine_mtp_phone_stays_visible()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_22D9&PID_2764\PHONE123456",
            Service = "WUDFWpdMtp",
            CompatibleIds = "USB\\MS_COMP_MTP"
        };
        DeviceTransportClassifier.Classify(device);
        Assert.Equal(DeviceKindResolver.PortableDevice, device.DeviceKind);
        Assert.False(DeviceComposition.IsFoldedByDefault(device));
        Assert.True(device.IsExternalDevice);
    }

    [Theory]
    [InlineData(@"BTHENUM\Dev_112233445566\7&TEST&BluetoothDevice_112233445566", "USB", "Сопряжённое Bluetooth-устройство")]
    [InlineData(@"USBSTOR\Disk&Ven_Test\SERIAL123&0", "DeviceInterface", "След устройства (DeviceClasses)")]
    public void Real_device_traces_keep_explicit_event_dates_even_with_old_support_category(string id, string type, string category)
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = id,
            DeviceType = type,
            VisualCategory = "SupportArtifact"
        };
        var when = new DateTimeOffset(2026, 9, 20, 12, 0, 0, TimeSpan.Zero);
        var result = new AuditResult
        {
            Devices = { device },
            Evidence =
            {
                new EvidenceRecord
                {
                    TimestampUtc = when,
                    Source = "setupapi.dev.log",
                    EvidenceCategory = "Установка/инициализация устройства",
                    DeviceHint = id,
                    CanEstablishConnectionDate = true
                }
            }
        };

        Assert.Equal(category, device.CategoryText);
        new TimelineEnricher().Enrich(result);
        Assert.Equal(when, device.FirstConnectedUtc);
        Assert.Contains("setupapi.dev.log", device.FirstConnectedProvenance);

        DeviceTransportClassifier.Classify(device);
        Assert.False(DeviceComposition.IsFoldedByDefault(device));
        Assert.NotEqual("SupportArtifact", device.VisualCategory);
    }

    [Fact]
    public void Bluetooth_services_and_driver_nodes_do_not_inflate_device_count()
    {
        var phone = new UsbDeviceRecord { DeviceInstanceId = @"BTHENUM\Dev_112233445566\PHONE" };
        var service = new UsbDeviceRecord
        {
            DeviceInstanceId = @"BTHENUM\{00001105-0000-1000-8000-00805f9b34fb}\SERVICE"
        };
        var driver = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SWD\DRIVERENUM\THUNDERBOLTHOSTCONTROLLERHSA&4&TEST&0"
        };
        DeviceTransportClassifier.ClassifyAll([phone, service, driver]);

        Assert.Equal("Bluetooth", phone.Connection);
        Assert.False(DeviceComposition.IsFoldedByDefault(phone));
        Assert.True(DeviceComposition.IsFoldedByDefault(service));
        Assert.True(DeviceComposition.IsFoldedByDefault(driver));
        var counts = DeviceCountSummary.FromDevices([phone, service, driver]);
        Assert.Equal(1, counts.PhysicalDevices);
        Assert.Equal(2, counts.InfrastructureRecords);
    }

    [Fact]
    public void Main_list_and_report_keep_usb_traces_and_skip_volume_dossiers()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_Test\SERIAL123&0",
            DeviceType = "DeviceInterface",
            VisualCategory = "SupportArtifact"
        };
        var volume = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SWD\WPDBUSENUM\{33e43465-a87f-11f1-986a-9010576eda10}\0000000000100000",
            FriendlyName = "TECHNICAL_VOLUME_ONLY",
            VisualCategory = "RealUsb"
        };
        var trace = new UsbDeviceRecord { DeviceType = "USBFlags", VisualCategory = "UsbFlagsTrace" };
        var result = new AuditResult { Devices = { device, volume, trace } };
        DeviceTransportClassifier.ClassifyAll(result.Devices);
        DeviceIdentityGraph.Process(result.Devices);
        var visible = result.Devices.Where(x => !DeviceComposition.IsFoldedByDefault(x)).ToList();

        Assert.Equal(2, visible.Count);
        Assert.Contains(device, visible);
        Assert.Contains(trace, visible);
        Assert.Equal(3, result.Devices.Count);
        var html = ForensicReportBuilder.BuildHtml(result);
        Assert.DoesNotContain("TECHNICAL_VOLUME_ONLY", html);
        Assert.Contains("След устройства (DeviceClasses)", html);
    }
}
