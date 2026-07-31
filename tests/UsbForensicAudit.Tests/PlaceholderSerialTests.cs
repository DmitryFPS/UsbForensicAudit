using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Шаблонный серийный номер принадлежит эталонной прошивке, а не изделию:
/// 0123456789ABCDEF встречается у множества не связанных между собой устройств.
/// Пока такой номер принимался за настоящий, на нём можно было построить вывод
/// «оба следа оставила одна и та же флешка».
/// </summary>
public class PlaceholderSerialTests
{
    [Theory]
    [InlineData("0123456789ABCDEF", true)]
    [InlineData("12345678", true)]
    [InlineData("ABCDEFGH", true)]
    [InlineData("87654321", true)]
    [InlineData("0123456789ABCDEF&0", true)]
    [InlineData("2412242109410569603146", false)]
    [InlineData("8dde262e", false)]
    [InlineData("A1B2C3D4", false)]
    [InlineData("12345", false)]
    [InlineData("", false)]
    public void Placeholder_serials_are_recognised(string serial, bool expected)
    {
        Assert.Equal(expected, DeviceIdentityTrust.IsPlaceholderSerial(serial));
    }

    [Fact]
    public void Dock_with_a_template_serial_is_flagged()
    {
        var findings = DeviceIdentityTrust.Assess(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_17EF&PID_F006\0123456789ABCDEF",
            Serial = "0123456789ABCDEF",
            Vid = "17EF",
            Pid = "F006",
            FriendlyName = "USB Composite Device"
        });

        Assert.Contains(findings, x => x.Title.Contains("значение по умолчанию"));
        Assert.Contains(findings, x => x.Severity == "High");
    }

    [Fact]
    public void Real_flash_drive_serial_is_not_flagged_as_a_template()
    {
        var findings = DeviceIdentityTrust.Assess(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk\2412242109410569603146&0",
            Serial = "2412242109410569603146"
        });

        Assert.DoesNotContain(findings, x => x.Title.Contains("значение по умолчанию"));
    }
}
