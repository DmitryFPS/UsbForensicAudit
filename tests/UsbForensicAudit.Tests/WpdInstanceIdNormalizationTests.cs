using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Один и тот же узел переносного устройства Windows хранит в двух видах: под
/// Enum имя ключа разделено решётками и заканчивается GUID класса интерфейса, а
/// в каталоге Portable Devices — обратными слешами и без GUID. Пока эти формы не
/// приводились к одной, одна флешка занимала во вкладке устройств две строки.
/// </summary>
public class WpdInstanceIdNormalizationTests
{
    [Fact]
    public void Both_registry_spellings_of_one_node_give_the_same_identifier()
    {
        const string enumKeyName =
            "_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00"
            + "#2412242109410569603146&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
        const string portableDevicesKeyName =
            "SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_GENERAL&PROD_UDISK&REV_5.00"
            + "#2412242109410569603146&0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}";

        var fromEnum = UsbRegistryForensicHelpers.BuildWpdInstanceId(
            UsbRegistryForensicHelpers.ParseWpdIdentity(enumKeyName));
        var fromPortableDevices = UsbRegistryForensicHelpers.BuildWpdInstanceId(
            UsbRegistryForensicHelpers.ParseWpdIdentity(portableDevicesKeyName));

        Assert.Equal(fromEnum, fromPortableDevices, ignoreCase: true);
        Assert.StartsWith(@"SWD\WPDBUSENUM\_??_USBSTOR\", fromEnum, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Phone_node_keeps_its_own_usb_identifier()
    {
        var identity = UsbRegistryForensicHelpers.ParseWpdIdentity("USB#VID_2717&PID_FF40#8DDE262E");

        Assert.Equal(@"USB\VID_2717&PID_FF40\8DDE262E", identity.DeviceInstanceId);
        Assert.Equal("8DDE262E", identity.Serial);
    }
}
