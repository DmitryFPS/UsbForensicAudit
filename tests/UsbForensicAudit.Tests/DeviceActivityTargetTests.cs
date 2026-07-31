using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Столбец «Папка или файл» должен содержать путь либо прямо говорить, что пути
/// в записи нет.
///
/// Часть записей папки не имеет вовсе: событие подключения называет устройство,
/// а запись проводника о подключении тома — GUID тома. Раньше эти идентификаторы
/// попадали в столбец пути, и у флешки без работы с файлами вся история выглядела
/// как перечень непонятных путей вида «SWD\WPDBUSENUM\_??_USBSTOR#Disk&amp;Ven_General
/// &amp;Prod_UDisk&amp;Rev_5.00#2412281911546114543745&amp;0#{53f56307-b6bf-11d0-94f2-…}».
/// </summary>
public class DeviceActivityTargetTests
{
    [Theory]
    [InlineData(@"USB\VID_ABCD&PID_1234\2412281911546114543745")]
    [InlineData(@"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412281911546114543745&0")]
    [InlineData(@"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412281911546114543745&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}")]
    [InlineData(@"STORAGE\Volume\_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412281911546114543745&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}")]
    public void Connection_record_says_there_is_no_folder_instead_of_showing_the_identifier(string identifier)
    {
        var entry = new DeviceActivityEntry
        {
            Kind = DeviceActivityKind.Connection,
            Path = identifier
        };

        Assert.Equal("Папки нет: это запись о подключении или отключении устройства", entry.PathText);
        Assert.Equal(identifier, entry.Path);
    }

    [Fact]
    public void Volume_that_explorer_remembered_is_named_as_a_volume_not_a_folder()
    {
        var entry = new DeviceActivityEntry
        {
            Kind = DeviceActivityKind.Mount,
            Path = "{F7821AA0-8B1D-11F1-9B5E-9010376EDA10}"
        };

        Assert.Equal("Папки нет: проводник запомнил том, а не папку", entry.PathText);
    }

    /// <summary>
    /// Настоящие пути должны остаться как есть: и на флешке, и в памяти телефона,
    /// и в сетевой папке.
    /// </summary>
    [Theory]
    [InlineData(@"E:\")]
    [InlineData(@"E:\Soft\картинки_згт")]
    [InlineData(@"POCO X3 NFC\Внутренний общий накопитель\DCIM")]
    [InlineData(@"\\20.20.20.76\r0\02. Документация личного состава")]
    public void Real_paths_are_shown_unchanged(string path)
    {
        var entry = new DeviceActivityEntry
        {
            Kind = DeviceActivityKind.FolderBrowse,
            Path = path
        };

        Assert.Equal(path, entry.PathText);
    }

    [Fact]
    public void Missing_path_is_stated_plainly()
    {
        var entry = new DeviceActivityEntry { Kind = DeviceActivityKind.FolderBrowse, Path = "" };

        Assert.Equal("Путь в артефакте не записан", entry.PathText);
    }

    /// <summary>
    /// Записи о подключении — не работа с файлами. Вывод «найдено 8 действий»
    /// читался так, будто на устройстве что-то открывали, хотя все восемь записей
    /// говорили лишь о том, что его втыкали.
    /// </summary>
    [Fact]
    public void History_of_connections_only_says_no_file_traces_were_found()
    {
        var history = new DeviceActivityHistory
        {
            CanSearchFileActivity = true,
            LinkKeys = ["GUID тома F7821AA0-8B1D-11F1-9B5E-9010376EDA10"],
            Entries =
            [
                new DeviceActivityEntry { Kind = DeviceActivityKind.Connection, Path = @"USB\VID_ABCD&PID_1234\2412" },
                new DeviceActivityEntry { Kind = DeviceActivityKind.Mount, Path = "{F7821AA0-8B1D-11F1-9B5E-9010376EDA10}" }
            ]
        };

        var verdict = history.Verdict();

        Assert.Contains("Следов работы с файлами не найдено", verdict);
        Assert.Contains("все 2 записей — о самом устройстве", verdict);
        Assert.DoesNotContain("Найдено 2 действий", verdict);
    }
}
