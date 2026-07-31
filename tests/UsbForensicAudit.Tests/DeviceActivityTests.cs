using System;
using System.Collections.Generic;
using System.Linq;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// История работы на устройстве отвечает на вопрос «куда ходили и что делали».
/// Главный риск здесь не пропустить след, а приписать чужой: проводник помнит
/// путь «E:\Фото», а не носитель, и буква диска за год достаётся разным флешкам.
/// Тесты закрепляют и находки, и честность оснований привязки.
/// </summary>
public class DeviceActivityTests
{
    private static readonly DateTimeOffset Moment = new(2026, 3, 14, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Folder_opened_on_the_device_drive_appears_in_the_history()
    {
        var device = FlashDrive("E:", "D16CE60D");
        var evidence = ShellBag(@"E:\Фото\Отпуск");

        var history = DeviceActivityBuilder.Build(device, [device], [evidence]);

        var entry = Assert.Single(history.Entries);
        Assert.Equal(DeviceActivityKind.FolderBrowse, entry.Kind);
        Assert.Equal(@"E:\Фото\Отпуск", entry.Path);
        Assert.Contains("Буква диска E:", entry.LinkBasis);
        Assert.Equal("Medium", entry.LinkConfidence);
    }

    /// <summary>
    /// Если буква побывала у нескольких носителей, вывод остаётся предположением
    /// и так и подписан — иначе действия одной флешки припишут другой.
    /// </summary>
    [Fact]
    public void Drive_letter_shared_by_two_devices_lowers_the_confidence()
    {
        var first = FlashDrive("E:", "D16CE60D");
        var second = FlashDrive("E:", "A1B2C3D4");
        second.DeviceInstanceId = @"USBSTOR\Disk&Ven_Kingston\9988776655&0";
        second.Serial = "9988776655";

        var history = DeviceActivityBuilder.Build(first, [first, second], [ShellBag(@"E:\Документы")]);

        var entry = Assert.Single(history.Entries);
        Assert.Equal("Low", entry.LinkConfidence);
        Assert.Contains("эту же букву носили и другие устройства", entry.LinkBasis);
        Assert.Contains("предположительно", entry.LinkText);
    }

    [Fact]
    public void Shortcut_with_the_exact_volume_serial_is_a_reliable_link()
    {
        var device = FlashDrive("E:", "D16CE60D");
        var lnk = new EvidenceRecord
        {
            TimestampUtc = Moment,
            Source = "User LNK Parsed",
            DeviceHint = @"E:\Отчёты\смета.xlsx",
            Summary = @"User LNK Parsed: E:\Отчёты\смета.xlsx",
            RawText = "VolumeSerial=D16C-E60D; VolumeLabel=FLASH; Target=E:\\Отчёты\\смета.xlsx"
        };

        var history = DeviceActivityBuilder.Build(device, [device], [lnk]);

        var entry = Assert.Single(history.Entries);
        Assert.Equal(DeviceActivityKind.FileOpen, entry.Kind);
        Assert.Equal("High", entry.LinkConfidence);
        Assert.Contains("Серийный номер тома D16CE60D", entry.LinkBasis);
    }

    [Fact]
    public void Deleted_file_from_the_device_is_reported_as_a_deletion()
    {
        var device = FlashDrive("E:", "D16CE60D");
        var recycle = new EvidenceRecord
        {
            TimestampUtc = Moment,
            Source = "Recycle Bin $I",
            DeviceHint = @"E:\Договоры\договор.pdf",
            RawText = @"OriginalPath=E:\Договоры\договор.pdf; OriginalSize=182344"
        };

        var history = DeviceActivityBuilder.Build(device, [device], [recycle]);

        Assert.Equal(DeviceActivityKind.FileDelete, Assert.Single(history.Entries).Kind);
    }

    [Fact]
    public void Program_started_from_the_device_is_reported_as_a_launch()
    {
        var device = FlashDrive("E:", "D16CE60D");
        var prefetch = new EvidenceRecord
        {
            TimestampUtc = Moment,
            Source = "Prefetch",
            DeviceHint = @"E:\Tools\usbdeview.exe"
        };

        var history = DeviceActivityBuilder.Build(device, [device], [prefetch]);

        Assert.Equal(DeviceActivityKind.ProgramRun, Assert.Single(history.Entries).Kind);
    }

    /// <summary>
    /// У телефона по MTP нет ни буквы диска, ни серийного номера тома: проводник
    /// сохраняет путь по видимому имени устройства.
    /// </summary>
    [Fact]
    public void Phone_folder_is_linked_by_the_name_shown_in_explorer()
    {
        var phone = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_Samsung#R58N7####&0",
            FriendlyName = "Galaxy A51",
            DeviceKind = DeviceKindResolver.PortableDevice
        };
        var shellbag = ShellBag(@"Galaxy A51\Внутренняя память\DCIM\Camera");

        var history = DeviceActivityBuilder.Build(phone, [phone], [shellbag]);

        var entry = Assert.Single(history.Entries);
        Assert.Equal("Medium", entry.LinkConfidence);
        Assert.Contains("Galaxy A51", entry.LinkBasis);
    }

    [Fact]
    public void Activity_of_another_device_is_not_attributed_to_this_one()
    {
        var device = FlashDrive("E:", "D16CE60D");

        var history = DeviceActivityBuilder.Build(device, [device], [ShellBag(@"F:\Чужая флешка")]);

        Assert.Empty(history.Entries);
    }

    /// <summary>
    /// Пустая история и невозможность поиска — разные вещи. Устройство без буквы
    /// диска и без серийного номера тома искать не по чему, и об этом надо
    /// сказать прямо, иначе пустой список прочитают как «ничего не делали».
    /// </summary>
    [Fact]
    public void Device_without_any_link_key_says_so_instead_of_showing_an_empty_list()
    {
        var hub = new UsbDeviceRecord { DeviceInstanceId = @"USB\ROOT_HUB30\4&1&0" };

        var history = DeviceActivityBuilder.Build(hub, [hub], [ShellBag(@"E:\Фото")]);

        Assert.False(history.CanSearchFileActivity);
        Assert.Empty(history.Entries);
        Assert.Contains("невозможность поиска", history.Verdict());
    }

    [Fact]
    public void Empty_history_with_link_keys_says_what_was_searched_for()
    {
        var device = FlashDrive("E:", "D16CE60D");

        var history = DeviceActivityBuilder.Build(device, [device], []);

        Assert.Contains("Следов работы с файлами не найдено", history.Verdict());
        Assert.Contains("буква диска E:", history.Verdict());
    }

    [Fact]
    public void Derived_correlation_records_are_not_user_actions()
    {
        var device = FlashDrive("E:", "D16CE60D");
        var correlation = new EvidenceRecord
        {
            TimestampUtc = Moment,
            Source = "Volume Correlation",
            DeviceHint = @"E:\",
            RawText = "VSN=D16CE60D"
        };

        var history = DeviceActivityBuilder.Build(device, [device], [correlation]);

        Assert.Empty(history.Entries);
    }

    [Fact]
    public void The_same_action_seen_in_two_artifacts_is_shown_once()
    {
        var device = FlashDrive("E:", "D16CE60D");
        var fromBag = ShellBag(@"E:\Фото");
        var fromMru = new EvidenceRecord
        {
            TimestampUtc = Moment,
            Source = "HKU LastVisitedPidlMRU",
            DeviceHint = @"E:\Фото"
        };

        var history = DeviceActivityBuilder.Build(device, [device], [fromBag, fromMru]);

        Assert.Single(history.Entries);
    }

    [Fact]
    public void Verdict_counts_folders_files_and_programs()
    {
        var device = FlashDrive("E:", "D16CE60D");
        var evidence = new List<EvidenceRecord>
        {
            ShellBag(@"E:\Фото"),
            ShellBag(@"E:\Документы"),
            new() { TimestampUtc = Moment, Source = "User LNK Parsed", DeviceHint = @"E:\смета.xlsx" },
            new() { TimestampUtc = Moment, Source = "Prefetch", DeviceHint = @"E:\Tools\run.exe" }
        };

        var history = DeviceActivityBuilder.Build(device, [device], evidence);

        Assert.Equal(2, history.FolderCount);
        Assert.Equal(1, history.FileCount);
        Assert.Equal(1, history.ProgramCount);
        Assert.Contains("папок открывали — 2", history.Verdict());
    }

    /// <summary>
    /// Windows не журналирует копирование. Совпадение имени файла на устройстве
    /// и на внутреннем диске — повод проверить, и в отчёте оно так и подписано.
    /// </summary>
    [Fact]
    public void Same_file_name_on_the_device_and_on_the_local_disk_is_flagged_as_a_lead()
    {
        var device = FlashDrive("E:", "D16CE60D");
        var onDevice = new EvidenceRecord
        {
            TimestampUtc = Moment,
            Source = "User LNK Parsed",
            DeviceHint = @"E:\Отчёты\квартальный отчёт.xlsx"
        };
        var onDisk = new EvidenceRecord
        {
            TimestampUtc = Moment.AddHours(1),
            Source = "HKU RecentDocs",
            DeviceHint = @"C:\Users\ivanov\Documents\квартальный отчёт.xlsx"
        };

        var history = DeviceActivityBuilder.Build(device, [device], [onDevice, onDisk]);

        var indication = Assert.Single(history.CopyIndications);
        Assert.Equal("квартальный отчёт.xlsx", indication.FileName);
        Assert.Equal(@"C:\Users\ivanov\Documents\квартальный отчёт.xlsx", indication.LocalPath);
        Assert.Contains("повод проверить, а не доказательство", history.CopyVerdict());
    }

    [Fact]
    public void Absence_of_copy_traces_is_not_reported_as_absence_of_copying()
    {
        var history = new DeviceActivityHistory();

        Assert.Contains("Windows не ведёт журнал копирования", history.CopyVerdict());
    }

    [Theory]
    [InlineData(@"C:\Temp\Документ1.docx")]
    [InlineData(@"C:\Temp\copy.txt")]
    [InlineData(@"C:\Temp\a.txt")]
    [InlineData(@"C:\Temp\Новый документ.txt")]
    public void Generic_file_names_never_become_a_copy_lead(string localPath)
    {
        var device = FlashDrive("E:", "D16CE60D");
        var name = localPath[(localPath.LastIndexOf('\\') + 1)..];
        var onDevice = new EvidenceRecord
        {
            TimestampUtc = Moment,
            Source = "User LNK Parsed",
            DeviceHint = $@"E:\{name}"
        };
        var onDisk = new EvidenceRecord
        {
            TimestampUtc = Moment.AddHours(1),
            Source = "HKU RecentDocs",
            DeviceHint = localPath
        };

        var history = DeviceActivityBuilder.Build(device, [device], [onDevice, onDisk]);

        Assert.Empty(history.CopyIndications);
    }

    [Fact]
    public void A_file_still_on_the_device_is_not_a_copy_lead()
    {
        var device = FlashDrive("E:", "D16CE60D");
        var first = new EvidenceRecord
        {
            TimestampUtc = Moment,
            Source = "User LNK Parsed",
            DeviceHint = @"E:\Отчёты\квартальный отчёт.xlsx"
        };
        var second = new EvidenceRecord
        {
            TimestampUtc = Moment.AddHours(1),
            Source = "HKU RecentDocs",
            DeviceHint = @"E:\Архив\квартальный отчёт.xlsx"
        };

        var history = DeviceActivityBuilder.Build(device, [device], [first, second]);

        Assert.Empty(history.CopyIndications);
    }

    [Fact]
    public void Every_entry_explains_what_its_timestamp_means()
    {
        var device = FlashDrive("E:", "D16CE60D");
        var evidence = new List<EvidenceRecord>
        {
            ShellBag(@"E:\Фото"),
            new() { TimestampUtc = Moment, Source = "User LNK Parsed", DeviceHint = @"E:\смета.xlsx" },
            new() { TimestampUtc = Moment, Source = "Recycle Bin $I", DeviceHint = @"E:\удалённый.pdf" }
        };

        var history = DeviceActivityBuilder.Build(device, [device], evidence);

        Assert.All(history.Entries, entry => Assert.False(string.IsNullOrWhiteSpace(entry.TimeMeaning)));
        Assert.Contains(history.Entries, x => x.TimeMeaning.Contains("удаления"));
    }

    [Fact]
    public void Newest_actions_come_first()
    {
        var device = FlashDrive("E:", "D16CE60D");
        var older = ShellBag(@"E:\Старое");
        var newer = ShellBag(@"E:\Новое");
        newer.TimestampUtc = Moment.AddDays(1);

        var history = DeviceActivityBuilder.Build(device, [device], [older, newer]);

        Assert.Equal(@"E:\Новое", history.Entries[0].Path);
    }

    private static UsbDeviceRecord FlashDrive(string driveLetter, string volumeSerial) => new()
    {
        DeviceInstanceId = @"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer\4C530001120523118563&0",
        Serial = "4C530001120523118563",
        FriendlyName = "SanDisk Cruzer",
        DeviceKind = DeviceKindResolver.Storage,
        DriveLetters = driveLetter,
        Volumes =
        [
            new VolumeIdentity { DriveLetter = driveLetter, VolumeSerialNumber = volumeSerial }
        ]
    };

    private static EvidenceRecord ShellBag(string path) => new()
    {
        TimestampUtc = Moment,
        Source = "Live HKU SID_Classes Shellbags",
        DeviceHint = path,
        Summary = $"Live HKU SID_Classes Shellbags: {path}",
        RegistryLastWriteUtc = Moment
    };
}
