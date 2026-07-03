using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class UserDisplayTextTests
{
    [Theory]
    [InlineData("RealUsb", "Реальное USB-устройство")]
    [InlineData("RelatedStorage", "Память или диск USB")]
    [InlineData("SupportArtifact", "Служебная запись Windows")]
    public void Category_maps_visual_categories(string input, string expected)
    {
        Assert.Equal(expected, UserDisplayText.Category(input));
    }

    [Theory]
    [InlineData("HIGH", "Высокий")]
    [InlineData("INFO", "Информация")]
    public void Severity_translates_levels(string input, string expected)
    {
        Assert.Equal(expected, UserDisplayText.Severity(input));
    }

    [Fact]
    public void Source_translates_registry_usb()
    {
        Assert.Equal("Реестр Windows — USB-устройства", UserDisplayText.Source("Registry: USB"));
    }

    [Fact]
    public void VidPidCodes_formats_partial_values()
    {
        Assert.Equal("VID 0951 / PID 1666", UserDisplayText.VidPidCodes("0951", "1666"));
        Assert.Equal("VID 0951", UserDisplayText.VidPidCodes("0951", ""));
    }

    [Fact]
    public void DeviceDisplayName_prefers_friendly_name()
    {
        var name = UserDisplayText.DeviceDisplayName("Kingston DT", "", "", @"USB\VID_0951");
        Assert.Equal("Kingston DT", name);
    }

    [Fact]
    public void ConnectionText_shows_moscow_time_for_exact_event()
    {
        var text = UserDisplayText.ConnectionText("ExactEvent", DateTimeOffset.Parse("2024-06-01T09:00:00Z"));
        Assert.Contains("МСК", text);
    }

    [Fact]
    public void DisconnectText_connected_now_when_device_active()
    {
        Assert.Equal(UserDisplayText.ConnectedNow, UserDisplayText.DisconnectText("ConnectedNow", null, true));
    }

    [Fact]
    public void Location_returns_fallback_when_empty()
    {
        Assert.Equal(UserDisplayText.NoLocationData, UserDisplayText.Location("", ""));
    }

    [Theory]
    [InlineData("ToolLaunch", "Запуск утилиты")]
    [InlineData("LogClearing", "Очистка журналов")]
    public void ActionKind_translates_values(string input, string expected)
    {
        Assert.Equal(expected, UserDisplayText.ActionKind(input));
    }

    [Theory]
    [InlineData("Normal", "Норма (после установки)")]
    [InlineData("Probable", "Вероятно")]
    public void Confidence_translates_values(string input, string expected)
    {
        Assert.Equal(expected, UserDisplayText.Confidence(input));
    }

    [Fact]
    public void DeviceType_translates_usb_categories()
    {
        Assert.Equal("USB-накопитель", UserDisplayText.DeviceType("USBSTOR"));
        Assert.Equal("USB-устройство", UserDisplayText.DeviceType("USB"));
    }

    [Fact]
    public void ManufacturerName_uses_vid_when_missing()
    {
        Assert.Equal("неизвестен (VID 0951)", UserDisplayText.ManufacturerName("", "", "0951"));
    }

    [Fact]
    public void ModelName_uses_product_with_revision()
    {
        Assert.Equal("DataTraveler G4 1.00", UserDisplayText.ModelName("DataTraveler G4", "", "1.00", "1666"));
    }

    [Fact]
    public void Serial_returns_placeholder_when_empty()
    {
        Assert.Equal("не указан", UserDisplayText.Serial(null));
    }

    [Fact]
    public void Assessment_translates_os_install()
    {
        Assert.Equal("Норма: ОС после установки", UserDisplayText.Assessment("OsInstall"));
    }

    [Fact]
    public void Area_translates_cleanup_sources()
    {
        Assert.Equal("Журналы Windows", UserDisplayText.Area("Event Logs"));
        Assert.Equal("Программы очистки следов", UserDisplayText.Area("Cleaner Artifacts"));
    }
}
