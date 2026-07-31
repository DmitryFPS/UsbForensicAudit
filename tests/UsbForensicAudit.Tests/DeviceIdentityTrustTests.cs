using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceIdentityTrustTests
{
    [Theory]
    [InlineData("7&2a1b3c4d&0", true)]
    [InlineData("5&1f2e3d4c&0&0000", true)]
    [InlineData("2412242109410569603146&0", false)]
    [InlineData("8dde262e", false)]
    public void Serial_invented_by_windows_is_recognised(string serial, bool expected)
    {
        Assert.Equal(expected, DeviceIdentityTrust.IsWindowsGeneratedSerial(serial));
    }

    [Fact]
    public void Generated_serial_is_reported_as_unusable_for_identification()
    {
        var findings = DeviceIdentityTrust.Assess(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_Generic&Prod_Flash\7&2a1b3c4d&0",
            Serial = "7&2a1b3c4d&0"
        });

        var finding = Assert.Single(findings, x => x.Title.Contains("придуман", StringComparison.Ordinal));
        Assert.Equal("High", finding.Severity);
        Assert.Contains("разъёму", finding.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void Real_serial_from_a_named_vendor_raises_nothing()
    {
        var findings = DeviceIdentityTrust.Assess(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_2717&PID_FF40\8dde262e",
            Serial = "8dde262e",
            Vid = "2717",
            Pid = "FF40",
            Manufacturer = "Xiaomi"
        });

        Assert.Empty(findings);
    }

    [Fact]
    public void Factory_default_vid_pid_pair_is_flagged()
    {
        var findings = DeviceIdentityTrust.Assess(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_0000&PID_0000\A1",
            Serial = "A1B2C3",
            Vid = "0000",
            Pid = "0000",
            Manufacturer = "Kingston"
        });

        Assert.Contains(findings, x => x.Title.Contains("Заводские значения", StringComparison.Ordinal));
    }

    [Fact]
    public void Non_hexadecimal_vid_cannot_be_genuine()
    {
        var findings = DeviceIdentityTrust.Assess(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_ZZZZ&PID_0001\A1",
            Serial = "A1B2C3",
            Vid = "ZZZZ",
            Pid = "0001",
            Manufacturer = "Kingston"
        });

        Assert.Contains(findings, x => x.Severity == "High" && x.Title.Contains("VID", StringComparison.Ordinal));
    }

    [Fact]
    public void Same_serial_across_different_models_means_it_identifies_nobody()
    {
        var results = DeviceIdentityTrust.AssessAll(
        [
            new UsbDeviceRecord
            {
                DeviceInstanceId = @"USB\VID_1111&PID_2222\SAMESERIAL",
                Serial = "SAMESERIAL", Vid = "1111", Pid = "2222", Manufacturer = "Kingston"
            },
            new UsbDeviceRecord
            {
                DeviceInstanceId = @"USB\VID_3333&PID_4444\SAMESERIAL",
                Serial = "SAMESERIAL", Vid = "3333", Pid = "4444", Manufacturer = "SanDisk"
            }
        ]);

        Assert.Equal(2, results.Count(x => x.Finding.Title.Contains("разных моделей", StringComparison.Ordinal)));
    }

    [Fact]
    public void Same_serial_on_the_same_model_is_just_one_device_seen_twice()
    {
        var results = DeviceIdentityTrust.AssessAll(
        [
            new UsbDeviceRecord
            {
                DeviceInstanceId = @"USB\VID_1111&PID_2222\SAMESERIAL",
                Serial = "SAMESERIAL", Vid = "1111", Pid = "2222", Manufacturer = "Kingston"
            },
            new UsbDeviceRecord
            {
                DeviceInstanceId = @"USBSTOR\Disk&Ven_Kingston\SAMESERIAL",
                Serial = "SAMESERIAL", Vid = "1111", Pid = "2222", Manufacturer = "Kingston"
            }
        ]);

        Assert.DoesNotContain(results, x => x.Finding.Title.Contains("разных моделей", StringComparison.Ordinal));
    }

    [Fact]
    public void Serial_made_of_one_repeated_character_is_not_unique()
    {
        Assert.True(DeviceIdentityTrust.IsRepeatedCharacterSerial("00000000&0"));
        Assert.True(DeviceIdentityTrust.IsRepeatedCharacterSerial("AAAAAAAA"));
        Assert.False(DeviceIdentityTrust.IsRepeatedCharacterSerial("2412242109410569603146&0"));
    }

    [Fact]
    public void Untrustworthy_identity_is_visible_on_the_record()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_Generic&Prod_Flash\7&2a1b&0",
            Serial = "7&2a1b&0"
        };
        device.IdentityTrustFindings.AddRange(DeviceIdentityTrust.Assess(device));

        Assert.True(device.IdentityIsUntrustworthy);
        Assert.Contains("придуман", device.IdentityTrustText, StringComparison.Ordinal);
    }

    [Fact]
    public void Clean_record_says_so_instead_of_staying_silent()
    {
        Assert.Equal("Идентификаторы выглядят достоверно.", new UsbDeviceRecord().IdentityTrustText);
    }
}
