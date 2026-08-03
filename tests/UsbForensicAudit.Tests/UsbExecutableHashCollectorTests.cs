using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Хеши исполнявшихся с USB файлов: извлечение путей .exe со съёмных томов из
/// артефактов запуска и подсчёт хешей через порт (с фейком, без файловой системы).
/// </summary>
public sealed class UsbExecutableHashCollectorTests
{
    private sealed class FakeHasher : IFileHasher
    {
        private readonly Dictionary<string, string> _hashes;
        public FakeHasher(Dictionary<string, string> hashes) => _hashes = hashes;

        public FileHashRecord Hash(string path) =>
            _hashes.TryGetValue(path, out var h)
                ? FileHashRecord.Ok(path, h, 100)
                : FileHashRecord.NotFoundAt(path);
    }

    private static AuditResult ResultWithRemovableExe()
    {
        var result = new AuditResult();
        result.Devices.Add(new UsbDeviceRecord
        {
            DeviceKind = DeviceKindResolver.Storage,
            DriveLetters = "E"
        });
        result.Evidence.Add(new EvidenceRecord
        {
            Source = "Prefetch",
            RawText = @"Запуск E:\tools\usbdeview.exe и C:\Windows\system32\cmd.exe"
        });
        return result;
    }

    [Fact]
    public void Extracts_only_exe_on_removable_drive()
    {
        var paths = UsbExecutableHashCollector.ExtractRemovableExePaths(ResultWithRemovableExe());

        Assert.Single(paths);
        Assert.Equal(@"E:\tools\usbdeview.exe", paths[0]);
    }

    [Fact]
    public void No_removable_drive_yields_no_paths()
    {
        var result = new AuditResult();
        result.Evidence.Add(new EvidenceRecord { Source = "Prefetch", RawText = @"D:\x.exe" });

        Assert.Empty(UsbExecutableHashCollector.ExtractRemovableExePaths(result));
    }

    [Fact]
    public void Non_execution_source_is_ignored()
    {
        var result = new AuditResult();
        result.Devices.Add(new UsbDeviceRecord { DeviceKind = DeviceKindResolver.Storage, DriveLetters = "E" });
        result.Evidence.Add(new EvidenceRecord { Source = "Реестр", RawText = @"E:\x.exe" });

        Assert.Empty(UsbExecutableHashCollector.ExtractRemovableExePaths(result));
    }

    [Fact]
    public void Collect_hashes_present_and_missing_files()
    {
        var hasher = new FakeHasher(new Dictionary<string, string>
        {
            [@"E:\tools\usbdeview.exe"] = "ABCD"
        });

        var records = UsbExecutableHashCollector.Collect(
            [@"E:\tools\usbdeview.exe", @"E:\gone.exe"], hasher);

        var hashed = records.First(x => x.Path.EndsWith("usbdeview.exe", StringComparison.Ordinal));
        Assert.Equal(FileHashStatus.Hashed, hashed.Status);
        Assert.Equal("ABCD", hashed.Sha256);

        var missing = records.First(x => x.Path.EndsWith("gone.exe", StringComparison.Ordinal));
        Assert.Equal(FileHashStatus.NotFound, missing.Status);
    }

    [Fact]
    public void Describe_empty_says_nothing_found()
    {
        Assert.Contains("не обнаружено", UsbExecutableHashCollector.Describe([]));
    }

    [Fact]
    public void Describe_counts_hashed_missing_and_failed()
    {
        var text = UsbExecutableHashCollector.Describe(
        [
            FileHashRecord.Ok(@"E:\a.exe", "AA", 1),
            FileHashRecord.NotFoundAt(@"E:\b.exe"),
            FileHashRecord.Failed(@"E:\c.exe", "denied")
        ]);

        Assert.Contains("3", text);
        Assert.Contains("хеши посчитаны: 1", text);
        Assert.Contains("файлы уже недоступны: 1", text);
        Assert.Contains("ошибки чтения: 1", text);
    }
}
