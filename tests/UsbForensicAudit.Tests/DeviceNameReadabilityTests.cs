using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Имя устройства во вкладке должно читаться человеком и занимать одну строку.
/// Значения взяты из реестра рабочей машины: Windows хранит имена ссылками на
/// строки внутри файлов драйверов, и без разбора во вкладке стояли ссылки.
/// </summary>
public class DeviceNameReadabilityTests
{
    [Theory]
    [InlineData(@"@bth.inf,%microsoft%;Microsoft", "Microsoft")]
    [InlineData(@"@usb.inf,%usb\composite.devicedesc%;USB Composite Device", "USB Composite Device")]
    [InlineData(@"@usbhub3.inf,%generic.mfg%;(Standard USB HUBs)", "Standard USB HUBs")]
    [InlineData(@"@input.inf,%stdmfg%;(Standard system devices)", "Standard system devices")]
    [InlineData(@"@System32\drivers\BthEnum.sys,#1;Периферийное устройство Bluetooth",
        "Периферийное устройство Bluetooth")]
    [InlineData(@"@oem34.inf,%ibt_usb%;Intel(R) Wireless Bluetooth(R)", "Intel(R) Wireless Bluetooth(R)")]
    public void Reference_to_a_driver_string_turns_into_the_name_behind_it(string stored, string expected) =>
        Assert.Equal(expected, IndirectString.Resolve(stored));

    /// <summary>
    /// Имя, которое владелец дал телефону, Windows дописывает отдельной строкой
    /// в скобках. Ради него разбор и нужен: это единственное место в отчёте, где
    /// видно, чей именно телефон был сопряжён.
    /// </summary>
    [Fact]
    public void Name_of_the_paired_phone_is_put_into_the_place_windows_left_for_it()
    {
        var stored = "@System32\\drivers\\bthhfenum.sys,#3;%1 Hands-Free HF%0\r\n;(Galaxy S9+ пользователь Дмитрий)";

        Assert.Equal("Galaxy S9+ пользователь Дмитрий Hands-Free HF", IndirectString.Resolve(stored));
    }

    [Fact]
    public void Substitution_in_the_middle_of_the_name_keeps_the_word_order()
    {
        var stored = "@System32\\drivers\\Microsoft.Bluetooth.AvrcpTransport.sys,#1;Транспорт AVRCP %1%0\r\n"
                     + ";(Galaxy S9+ пользователь Дмитрий)";

        Assert.Equal("Транспорт AVRCP Galaxy S9+ пользователь Дмитрий", IndirectString.Resolve(stored));
    }

    /// <summary>
    /// Строка таблицы имеет одну высоту, и перевод строки внутри имени рвал её
    /// надвое: вторая половина выглядела как запись без данных в других клетках.
    /// </summary>
    [Fact]
    public void Name_never_takes_two_lines()
    {
        var stored = "@System32\\drivers\\btha2dp.sys,#2;%1 A2DP SNK%0\r\n;(Galaxy S9+ пользователь Дмитрий)";

        var resolved = IndirectString.Resolve(stored);

        Assert.DoesNotContain('\r', resolved);
        Assert.DoesNotContain('\n', resolved);
        Assert.Equal("Galaxy S9+ пользователь Дмитрий A2DP SNK", resolved);
    }

    /// <summary>
    /// Выдумывать имя вместо Windows нельзя: ссылка без запасного текста
    /// означает, что читаемого имени в реестре нет.
    /// </summary>
    [Fact]
    public void Reference_without_a_readable_part_gives_nothing()
    {
        Assert.Equal("", IndirectString.Resolve("@bthenum.sys,-1000"));
        Assert.Equal("", IndirectString.Resolve(""));
    }

    [Fact]
    public void Plain_name_stays_as_it_was()
    {
        Assert.Equal("Galaxy S9+ пользователь Дмитрий",
            IndirectString.Resolve("Galaxy S9+ пользователь Дмитрий"));
        Assert.Equal("T-FORCE TM8FPL500G", IndirectString.Resolve("T-FORCE TM8FPL500G"));
    }

    [Fact]
    public void Display_name_of_a_device_no_longer_shows_a_reference()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_0458&PID_0186\5&393a40ce&0&7",
            FriendlyName = @"@usb.inf,%usb\composite.devicedesc%;USB Composite Device",
            Manufacturer = @"@usb.inf,%generic.mfg%;(Стандартный USB хост-контроллер)",
            Product = @"@usb.inf,%usb\composite.devicedesc%;USB Composite Device"
        };

        Assert.Equal("USB Composite Device", device.DisplayName);
        Assert.Equal("Стандартный USB хост-контроллер", device.ManufacturerText);
        Assert.Equal("USB Composite Device", device.ModelText);
    }

    /// <summary>
    /// Имя производителя, уже стоящее в названии модели, повторять незачем:
    /// «Microsoft Microsoft Bluetooth A2dp Sink» читается как ошибка программы.
    /// </summary>
    [Fact]
    public void Vendor_name_is_not_repeated_twice_in_a_row()
    {
        var device = new UsbDeviceRecord
        {
            Manufacturer = @"@microsoft_bluetooth_a2dp_snk.inf,%microsoft%;Microsoft",
            Product = @"@microsoft_bluetooth_a2dp_snk.inf,%btha2dpsnk.devicedescription%;Microsoft Bluetooth A2dp Sink"
        };

        Assert.Equal("Microsoft Bluetooth A2dp Sink", device.DisplayName);
    }

    /// <summary>
    /// Запись без единого читаемого имени показывает идентификатор: он хотя бы
    /// проверяем по реестру, а пустая клетка не говорит ничего.
    /// </summary>
    [Fact]
    public void Record_without_any_readable_name_falls_back_to_the_identifier()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"BTHENUM\{00001800-0000-1000-8000-00805f9b34fb}_VID&00010075_PID&0100\7&2768a9f8",
            FriendlyName = "",
            Manufacturer = "",
            Product = "@nowhere.sys,-1"
        };

        Assert.Equal(device.DeviceInstanceId, device.DisplayName);
    }
}
