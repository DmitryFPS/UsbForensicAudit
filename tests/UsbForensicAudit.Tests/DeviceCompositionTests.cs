using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Список показывает устройства, а не строки реестра. Проверяется, что в
/// строке стоит само устройство с человеческим именем, что его записи никуда
/// не потерялись и что перечень услуг сопряжённого телефона остаётся доступен:
/// именно по нему видно, что через соединение было можно.
/// </summary>
public class DeviceCompositionTests
{
    [Fact]
    public void Phone_takes_one_row_and_keeps_its_services()
    {
        var devices = PairedPhoneWithServices();
        DeviceIdentityGraph.Process(devices);

        var shown = devices.Where(x => !DeviceComposition.IsFoldedByDefault(x)).ToList();
        var phone = Assert.Single(shown);
        Assert.Equal(@"BTHENUM\Dev_887598C2F5F2\7&2768a9f8&0&BluetoothDevice_887598C2F5F2", phone.DeviceInstanceId);

        var parts = DeviceComposition.PartsOf(phone, devices);
        Assert.Equal(2, parts.Count);

        var composition = DeviceComposition.Describe(phone, devices);
        Assert.Contains("Microsoft Object Push Service", composition);
        Assert.Contains("Microsoft Phonebook Access Pse Service", composition);
    }

    [Fact]
    public void Camera_of_the_laptop_is_one_row_named_by_its_function()
    {
        var devices = CompositeCamera();
        DeviceIdentityGraph.Process(devices);

        var shown = devices.Where(x => !DeviceComposition.IsFoldedByDefault(x)).ToList();
        var camera = Assert.Single(shown);

        // Windows зовёт саму запись по классу — «USB Composite Device», — а
        // модель пишет у её функции. В списке должна стоять камера.
        Assert.Equal(@"USB\VID_30C9&PID_00F8\01.00.00", camera.DeviceInstanceId);
        Assert.Equal("Integrated Camera", camera.DisplayName);
        Assert.Equal("USB Composite Device", camera.OwnDisplayName);
        Assert.Contains(camera.IdentityProvenance, x => x.Contains("MI_00"));
    }

    [Fact]
    public void Nothing_disappears_when_all_records_are_asked_for()
    {
        var devices = PairedPhoneWithServices().Concat(CompositeCamera()).ToList();
        DeviceIdentityGraph.Process(devices);

        var shown = devices.Where(x => !DeviceComposition.IsFoldedByDefault(x)).ToList();
        var folded = devices.Where(DeviceComposition.IsFoldedByDefault).ToList();

        Assert.Equal(devices.Count, shown.Count + folded.Count);
        foreach (var part in folded)
        {
            var owner = shown.Single(x => x.CanonicalDeviceId == part.CanonicalDeviceId);
            Assert.Contains(part, DeviceComposition.PartsOf(owner, devices));
        }
    }

    [Fact]
    public void Record_without_a_group_stays_in_the_list()
    {
        var lonely = Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_Kingston\0123&0",
            Service = "disk"
        });

        Assert.False(DeviceComposition.IsFoldedByDefault(lonely));
    }

    private static List<UsbDeviceRecord> PairedPhoneWithServices()
    {
        const string container = "{82e332c1-0e1a-5123-843d-132f3a51b2f8}";
        return
        [
            Classified(new UsbDeviceRecord
            {
                DeviceInstanceId = @"BTHENUM\Dev_887598C2F5F2\7&2768a9f8&0&BluetoothDevice_887598C2F5F2",
                FriendlyName = "Galaxy S9+ пользователя Дмитрий",
                ContainerId = container,
                Source = "Registry: Bluetooth"
            }),
            Classified(new UsbDeviceRecord
            {
                DeviceInstanceId = @"BTHENUM\{00001105-0000-1000-8000-00805f9b34fb}_VID&00010075_PID&0100\7&2768a9f8&0&887598C2F5F2_C00000000",
                FriendlyName = "Microsoft Object Push Service",
                ContainerId = container,
                Source = "Registry: Bluetooth"
            }),
            Classified(new UsbDeviceRecord
            {
                DeviceInstanceId = @"BTHENUM\{0000112f-0000-1000-8000-00805f9b34fb}_VID&00010075_PID&0100\7&2768a9f8&0&887598C2F5F2_C00000000",
                FriendlyName = "Microsoft Phonebook Access Pse Service",
                ContainerId = container,
                Source = "Registry: Bluetooth"
            })
        ];
    }

    /// <summary>
    /// Встроенная камера ноутбука: у самой записи в пути стоит её серийный
    /// номер, у граней — выданный Windows номер. Сходятся они только по
    /// родительскому префиксу.
    /// </summary>
    private static List<UsbDeviceRecord> CompositeCamera() =>
    [
        Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_30C9&PID_00F8\01.00.00",
            FriendlyName = "USB Composite Device",
            ParentIdPrefix = "6&3ad2d465&0",
            Source = "Registry: USB",
            Vid = "30C9",
            Pid = "00F8"
        }),
        Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_30C9&PID_00F8&MI_00\6&3ad2d465&0&0000",
            FriendlyName = "Integrated Camera",
            Source = "Registry: USB",
            Vid = "30C9",
            Pid = "00F8"
        }),
        Classified(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_30C9&PID_00F8&MI_02\6&3ad2d465&0&0002",
            FriendlyName = "APP Mode",
            Source = "Registry: USB",
            Vid = "30C9",
            Pid = "00F8"
        })
    ];

    private static UsbDeviceRecord Classified(UsbDeviceRecord device)
    {
        DeviceTransportClassifier.Classify(device);
        return device;
    }
}
