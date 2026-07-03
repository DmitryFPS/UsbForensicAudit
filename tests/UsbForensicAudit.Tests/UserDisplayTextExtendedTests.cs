using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class UserDisplayTextExtendedTests
{
    [Theory]
    [InlineData("Registry: USB", "Реестр Windows — USB-устройства")]
    [InlineData("EventLog:System", "Журнал Windows — System")]
    [InlineData("Prefetch", "Prefetch — следы запуска программ")]
    [InlineData("Correlation", "Автоматическая связь данных")]
    [InlineData("Журнал контроля USB", "Журнал корпоративной защиты USB (DLP)")]
    public void Source_translates_known_sources(string input, string expected)
    {
        Assert.Equal(expected, UserDisplayText.Source(input));
    }

    [Theory]
    [InlineData("Даты взяты из журнала Windows", "наиболее надёжные")]
    [InlineData("Служебный артефакт", "служебная запись Windows")]
    [InlineData("Сейчас не подключено", "точное время отключения")]
    public void DateConfidence_rewrites_known_phrases(string input, string fragment)
    {
        Assert.Contains(fragment, UserDisplayText.DateConfidence(input), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DeviceDisplayName_builds_from_manufacturer_and_product()
    {
        var name = UserDisplayText.DeviceDisplayName(@"USB\VID_0951&PID_1666", "Kingston", "DT", "id");
        Assert.Equal("Kingston DT", name);
    }

    [Theory]
    [InlineData("OK", "Работает")]
    [InlineData("Degraded", "Ограничено")]
    [InlineData("Unknown", "Неизвестно")]
    public void DeviceStatus_translates_wmi(string status, string expected)
    {
        Assert.Equal(expected, UserDisplayText.DeviceStatus(status, "generic"));
    }

    [Fact]
    public void DeviceStatus_usb_error_explains_dlp()
    {
        var text = UserDisplayText.DeviceStatus("Error", @"USB\VID_0951&PID_1666");
        Assert.Contains("WMI", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DisconnectText_exact_event_with_reconnect()
    {
        var ts = DateTimeOffset.Parse("2024-06-01T09:00:00Z");
        var text = UserDisplayText.DisconnectText("ExactEvent", ts, isCurrentlyConnected: true);
        Assert.Contains("снова подключено", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ConnectionText_registry_activity_adds_hint()
    {
        var ts = DateTimeOffset.Parse("2024-06-01T09:00:00Z");
        var text = UserDisplayText.ConnectionText("RegistryActivity", ts);
        Assert.Contains("реестре", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ManufacturerName_splits_friendly_name()
    {
        Assert.Equal("Kingston", UserDisplayText.ManufacturerName("", "Kingston DataTraveler", ""));
    }

    [Fact]
    public void ModelName_strips_usb_device_suffix()
    {
        Assert.Equal("Kingston", UserDisplayText.ModelName("", "Kingston USB Device", "", ""));
    }

    [Fact]
    public void InitiatorDisplay_delegates_to_cleanup_attribution()
    {
        var text = UserDisplayText.InitiatorDisplay("System", "SYSTEM");
        Assert.False(string.IsNullOrWhiteSpace(text));
    }
}

public class ReportTextExtendedTests
{
    [Fact]
    public void ForPdf_redacts_and_normalizes()
    {
        var text = ReportText.ForPdf("Secret Net Studio USB check");
        Assert.Contains("корпоративная защита USB", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ForDisplayOrClean_keeps_generated_explanations()
    {
        var text = ReportText.ForDisplayOrClean("Prefetch: USBDeview.exe запуск");
        Assert.Contains("Prefetch", text, StringComparison.OrdinalIgnoreCase);
    }
}

public class ProcmonClassifierExtendedTests
{
    [Fact]
    public void Classify_covers_mru_and_device_classes()
    {
        Assert.Equal("MRU пользователя", ProcmonRegistryPathClassifier.Classify(@"HKU\...\OpenSavePidlMRU").Title);
        Assert.Equal("DeviceClasses", ProcmonRegistryPathClassifier.Classify(@"HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{guid}").Title);
        Assert.Equal("WPD Devices", ProcmonRegistryPathClassifier.Classify(@"HKLM\...\Windows Portable Devices\Devices\abc").Title);
    }
}
