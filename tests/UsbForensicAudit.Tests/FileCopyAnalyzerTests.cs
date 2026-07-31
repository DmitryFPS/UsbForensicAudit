using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Перенос файлов — самый сильный вывод программы и самый опасный: обвинение в
/// выносе данных не должно строиться на совпадении имён. Поэтому проверяется не
/// только то, что перенос находится, но и то, что программа не приписывает
/// направление, которого из данных не видно.
/// </summary>
public class FileCopyAnalyzerTests
{
    private static readonly DateTimeOffset DeviceMoment = new(2026, 3, 14, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void File_appearing_on_disk_next_to_the_device_session_is_reported_as_a_transfer()
    {
        var result = ResultWithDeviceActivity(@"E:\Отчёты\годовая смета.xlsx", DeviceMoment);
        var changes = ChangeSet(Change("годовая смета.xlsx", @"C:\Users\adm\Documents\годовая смета.xlsx",
            DeviceMoment.AddMinutes(2)));

        FileCopyAnalyzer.Process(result, changes);

        var indication = Assert.Single(result.Devices[0].CopyIndications);
        Assert.Equal("годовая смета.xlsx", indication.FileName);
        Assert.Equal("High", indication.Confidence);
        Assert.Equal(@"C:\Users\adm\Documents\годовая смета.xlsx", indication.LocalPath);
        Assert.Contains("журнала изменений NTFS", indication.Basis, StringComparison.Ordinal);
    }

    [Fact]
    public void Direction_is_left_undecided_when_the_events_are_minutes_apart()
    {
        var result = ResultWithDeviceActivity(@"E:\Отчёты\смета.xlsx", DeviceMoment);
        var changes = ChangeSet(Change("смета.xlsx", @"C:\Users\adm\Documents\смета.xlsx",
            DeviceMoment.AddMinutes(1)));

        FileCopyAnalyzer.Process(result, changes);

        var indication = Assert.Single(result.Devices[0].CopyIndications);
        Assert.Equal(CopyDirection.Unknown, indication.Direction);
        Assert.Contains("Направление по такому короткому промежутку определить нельзя",
            indication.Basis, StringComparison.Ordinal);
    }

    [Fact]
    public void File_appearing_on_disk_long_after_the_device_session_points_at_the_computer()
    {
        var result = ResultWithDeviceActivity(@"E:\Архив\проект.zip", DeviceMoment);
        var changes = ChangeSet(Change("проект.zip", @"C:\Users\adm\Downloads\проект.zip",
            DeviceMoment.AddHours(3)));

        FileCopyAnalyzer.Process(result, changes);

        var indication = Assert.Single(result.Devices[0].CopyIndications);
        Assert.Equal(CopyDirection.ToComputer, indication.Direction);
        Assert.Equal("Medium", indication.Confidence);
    }

    [Fact]
    public void File_that_lay_on_disk_long_before_the_device_session_points_at_the_device()
    {
        var result = ResultWithDeviceActivity(@"E:\Копия\база.accdb", DeviceMoment);
        var changes = ChangeSet(Change("база.accdb", @"C:\Работа\база.accdb", DeviceMoment.AddDays(-30)));

        FileCopyAnalyzer.Process(result, changes);

        var indication = Assert.Single(result.Devices[0].CopyIndications);
        Assert.Equal(CopyDirection.ToDevice, indication.Direction);
        Assert.Equal("С компьютера на устройство", indication.DirectionText);
    }

    [Fact]
    public void Deleting_a_file_on_disk_is_not_a_sign_that_it_was_brought_from_the_device()
    {
        var result = ResultWithDeviceActivity(@"E:\Отчёты\смета.xlsx", DeviceMoment);
        var deletion = Change("смета.xlsx", @"C:\Users\adm\Documents\смета.xlsx", DeviceMoment.AddMinutes(1));
        deletion.Kind = FileChangeKind.Deleted;

        FileCopyAnalyzer.Process(result, ChangeSet(deletion));

        Assert.Empty(result.Devices[0].CopyIndications);
    }

    [Fact]
    public void Files_that_never_appeared_on_disk_produce_no_indication()
    {
        var result = ResultWithDeviceActivity(@"E:\Отчёты\секретно.xlsx", DeviceMoment);
        var changes = ChangeSet(Change("другое.docx", @"C:\Users\adm\Documents\другое.docx", DeviceMoment));

        FileCopyAnalyzer.Process(result, changes);

        Assert.Empty(result.Devices[0].CopyIndications);
    }

    [Fact]
    public void Journal_depth_is_kept_even_when_nothing_was_found()
    {
        var result = ResultWithDeviceActivity(@"E:\Отчёты\секретно.xlsx", DeviceMoment);
        var journal = new FileChangeJournalState
        {
            Volume = "C:",
            Available = true,
            OldestRecordUtc = DeviceMoment.AddDays(-2),
            NewestRecordUtc = DeviceMoment
        };

        FileCopyAnalyzer.Process(result, new FileSystemChangeSet([], [journal]));

        var kept = Assert.Single(result.FileChangeJournals);
        Assert.Contains("покрывает период", kept.CoverageText, StringComparison.Ordinal);
    }

    [Fact]
    public void Verdict_names_the_journal_period_so_that_nothing_found_is_not_read_as_nothing_happened()
    {
        var result = ResultWithDeviceActivity(@"E:\Отчёты\секретно.xlsx", DeviceMoment);
        result.FileChangeJournals.Add(new FileChangeJournalState
        {
            Volume = "C:",
            Available = true,
            OldestRecordUtc = DeviceMoment.AddDays(-2),
            NewestRecordUtc = DeviceMoment
        });

        var history = DeviceActivityBuilder.Build(result.Devices[0], result);

        Assert.Contains("Признаков переноса файлов не найдено", history.CopyVerdict(), StringComparison.Ordinal);
        Assert.Contains("затирается по кругу", history.CopyVerdict(), StringComparison.Ordinal);
    }

    [Fact]
    public void Verdict_says_when_the_journal_could_not_be_read_at_all()
    {
        var result = ResultWithDeviceActivity(@"E:\Отчёты\секретно.xlsx", DeviceMoment);

        var history = DeviceActivityBuilder.Build(result.Devices[0], result);

        Assert.Contains("Журнал изменений NTFS прочитать не удалось",
            history.CopyVerdict(), StringComparison.Ordinal);
    }

    [Fact]
    public void Findings_from_the_journal_survive_a_rebuild_of_the_history()
    {
        var result = ResultWithDeviceActivity(@"E:\Отчёты\смета.xlsx", DeviceMoment);
        FileCopyAnalyzer.Process(result, ChangeSet(Change("смета.xlsx",
            @"C:\Users\adm\Documents\смета.xlsx", DeviceMoment.AddMinutes(1))));

        var history = DeviceActivityBuilder.Build(result.Devices[0], result);

        var indication = Assert.Single(history.CopyIndications);
        Assert.Equal("High", indication.Confidence);
        Assert.Contains("подтверждены журналом изменений NTFS",
            history.CopyVerdict(), StringComparison.Ordinal);
    }

    [Fact]
    public void One_file_is_reported_once_even_when_touched_on_the_device_repeatedly()
    {
        var result = ResultWithDeviceActivity(@"E:\Отчёты\смета.xlsx", DeviceMoment);
        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = DeviceMoment.AddMinutes(5),
            Source = "User LNK Parsed",
            DeviceHint = @"E:\Отчёты\смета.xlsx"
        });

        FileCopyAnalyzer.Process(result, ChangeSet(Change("смета.xlsx",
            @"C:\Users\adm\Documents\смета.xlsx", DeviceMoment.AddMinutes(1))));

        Assert.Single(result.Devices[0].CopyIndications);
    }

    [Fact]
    public void Filter_keeps_user_documents_and_drops_service_files()
    {
        Assert.True(FileChangeJournalCollector.IsInteresting(
            Entry("смета отдела.xlsx", UsnJournalEntry.ReasonFileCreate)));
        Assert.False(FileChangeJournalCollector.IsInteresting(
            Entry("Windows.edb.log", UsnJournalEntry.ReasonFileCreate)));
        Assert.False(FileChangeJournalCollector.IsInteresting(
            Entry("~$смета.xlsx", UsnJournalEntry.ReasonFileCreate)));
        Assert.False(FileChangeJournalCollector.IsInteresting(
            Entry("Фото", UsnJournalEntry.ReasonFileCreate, attributes: 0x10)));
        Assert.False(FileChangeJournalCollector.IsInteresting(
            Entry("безрасширения", UsnJournalEntry.ReasonFileCreate)));
    }

    [Fact]
    public void Filter_ignores_windows_own_folders_but_keeps_user_folders()
    {
        Assert.True(FileChangeJournalCollector.IsIgnoredPath(@"C:\Windows\System32"));
        Assert.True(FileChangeJournalCollector.IsIgnoredPath(@"C:\Users\adm\AppData\Local\Temp\x"));
        Assert.False(FileChangeJournalCollector.IsIgnoredPath(@"C:\Users\adm\Documents"));
        Assert.False(FileChangeJournalCollector.IsIgnoredPath(@"D:\Работа\Отчёты"));
    }

    [Fact]
    public void Disabled_journal_is_described_rather_than_silently_skipped()
    {
        var state = new FileChangeJournalState
        {
            Volume = "D:",
            Available = false,
            Note = "Журнал изменений на этом томе выключен."
        };

        Assert.Contains("недоступен", state.CoverageText, StringComparison.Ordinal);
        Assert.Contains("выключен", state.CoverageText, StringComparison.Ordinal);
    }

    /// <summary>
    /// Запись внутреннего диска тоже имеет букву, и по ней к ней притягивается вся
    /// локальная файловая активность. Сравнивать её с журналом того же диска —
    /// значит сопоставлять файл сам с собой и выдавать это за перенос.
    /// </summary>
    [Fact]
    public void Records_of_internal_disks_are_not_checked_for_transfers()
    {
        var result = ResultWithDeviceActivity(@"D:\Работа\квартальный отчёт.xlsx", DeviceMoment);
        result.Devices[0].DeviceInstanceId = @"STORAGE\Volume\{guid}#0000000000100000";
        result.Devices[0].FriendlyName = "Диск D";
        result.Devices[0].DriveLetters = "D:";
        result.Devices[0].Volumes = [new VolumeIdentity { DriveLetter = "D:" }];
        DeviceTransportClassifier.Classify(result.Devices[0]);

        FileCopyAnalyzer.Process(result, ChangeSet(Change("квартальный отчёт.xlsx",
            @"C:\Users\adm\Documents\квартальный отчёт.xlsx", DeviceMoment.AddMinutes(1))));

        Assert.Empty(result.Devices[0].CopyIndications);
    }

    [Fact]
    public void Path_on_an_internal_volume_is_not_treated_as_a_path_on_the_device()
    {
        var result = ResultWithDeviceActivity(@"D:\Софт\установщик программы.exe", DeviceMoment);

        FileCopyAnalyzer.Process(result, ChangeSet(Change("установщик программы.exe",
            @"C:\Users\adm\Downloads\установщик программы.exe", DeviceMoment.AddMinutes(1))));

        Assert.Empty(result.Devices[0].CopyIndications);
    }

    [Fact]
    public void The_same_file_is_not_matched_with_itself()
    {
        var result = ResultWithDeviceActivity(@"E:\Отчёты\смета отдела.xlsx", DeviceMoment);

        FileCopyAnalyzer.Process(result, ChangeSet(Change("смета отдела.xlsx",
            @"E:\Отчёты\смета отдела.xlsx", DeviceMoment.AddMinutes(1))));

        Assert.Empty(result.Devices[0].CopyIndications);
    }

    private static AuditResult ResultWithDeviceActivity(string pathOnDevice, DateTimeOffset moment)
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer\4C530001&0",
            CanonicalDeviceId = "4C530001",
            Serial = "4C530001",
            FriendlyName = "SanDisk Cruzer",
            DriveLetters = "E:",
            Volumes = [new VolumeIdentity { DriveLetter = "E:", VolumeSerialNumber = "D16CE60D" }]
        };
        DeviceTransportClassifier.Classify(device);

        var result = new AuditResult();
        result.Devices.Add(device);
        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = moment,
            Source = "User LNK Parsed",
            DeviceHint = pathOnDevice
        });
        return result;
    }

    private static FileChangeRecord Change(string name, string path, DateTimeOffset moment) => new()
    {
        FileName = name,
        Path = path,
        TimestampUtc = moment,
        Kind = FileChangeKind.Created,
        Volume = "C:"
    };

    /// <summary>
    /// Внутренние тома перечисляются так же, как это делает сборщик: том D:
    /// внутренний, даже если журнал на нём выключен.
    /// </summary>
    private static FileSystemChangeSet ChangeSet(params FileChangeRecord[] changes) =>
        new(changes,
        [
            new FileChangeJournalState
            {
                Volume = "C:",
                Available = true,
                OldestRecordUtc = changes.Min(x => x.TimestampUtc).AddDays(-1),
                NewestRecordUtc = changes.Max(x => x.TimestampUtc)
            },
            new FileChangeJournalState
            {
                Volume = "D:",
                Available = false,
                Note = "Журнал изменений на этом томе выключен."
            }
        ]);

    private static UsnJournalEntry Entry(string name, uint reason, uint attributes = 0x20) =>
        new(0x10, 1, DeviceMoment, reason, attributes, name);
}
