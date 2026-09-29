using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class LiveAuditRegressionTests
{
    [Fact]
    public void Open_wal_database_package_includes_latest_commit_and_excludes_uncommitted_writes()
    {
        var directory = Directory.CreateTempSubdirectory("ufa-wal-").FullName;
        try
        {
            var database = Path.Combine(directory, "audit.sqlite");
            using var writer = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = database, Pooling = false }.ToString());
            writer.Open();
            using var command = writer.CreateCommand();
            command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE expert_notes(note TEXT);";
            command.ExecuteNonQuery();
            command.CommandText = "INSERT INTO expert_notes VALUES ('Контрольная заметка аудита');";
            command.ExecuteNonQuery();
            Assert.True(new FileInfo(database + "-wal").Length > 0);
            using var transaction = writer.BeginTransaction();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO expert_notes VALUES ('Не сохранено');";
            command.ExecuteNonQuery();

            var zipPath = Path.Combine(directory, "package.zip");
            EvidencePackageBuilder.Build(zipPath, [database], sqliteDatabasePath: database);
            using var archive = ZipFile.OpenRead(zipPath);
            var entry = archive.GetEntry("audit.sqlite")!;
            var snapshot = Path.Combine(directory, "restored.sqlite");
            entry.ExtractToFile(snapshot);
            using var manifest = JsonDocument.Parse(archive.GetEntry("manifest.json")!.Open());
            var hash = manifest.RootElement.GetProperty("Files")[0].GetProperty("Sha256").GetString();
            Assert.Equal(hash, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(snapshot))));
            using var reader = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = snapshot, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
            reader.Open();
            using var query = reader.CreateCommand();
            query.CommandText = "SELECT group_concat(note) FROM expert_notes;";
            Assert.Equal("Контрольная заметка аудита", query.ExecuteScalar());
            query.CommandText = "PRAGMA integrity_check;";
            Assert.Equal("ok", query.ExecuteScalar());
            Assert.Empty(Directory.GetFiles(directory, "*.tmp*"));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void Connection_mount_and_inventory_are_preserved_in_dossier_but_not_called_file_actions()
    {
        var result = Sample();
        var device = result.Devices[0];
        result.Evidence.Add(new EvidenceRecord { Source = "setupapi.dev.log", DeviceHint = device.DeviceInstanceId });
        result.Evidence.Add(new EvidenceRecord { Source = "HKU MountPoints2", DeviceHint = device.DeviceInstanceId });
        result.Evidence.Add(new EvidenceRecord { Source = "Amcache Inventory Parsed", DeviceHint = device.DeviceInstanceId });
        var ctx = Context(result);
        Assert.NotEmpty(ctx.GetActivity(device).Entries);
        Assert.Empty(ctx.DevicesWithActivity());
        Assert.Equal("Следов работы с файлами не найдено", KeyAnswersContent.Build(ctx)[1].Verdict);
        Assert.DoesNotContain("Восстановлена работа", ctx.ActivityVerdict());

        result.Evidence.Add(new EvidenceRecord { Source = "LNK", DeviceHint = @"E:\отчёт.txt" });
        var after = Context(result);
        var history = Assert.Single(after.DevicesWithActivity()).History;
        Assert.Equal(DeviceActivityKind.FileOpen, Assert.Single(history.Entries).Kind);
        Assert.Contains("1 действ.(ий) на 1", KeyAnswersContent.Build(after)[1].Verdict);
        Assert.True(after.GetActivity(device).Entries.Count > history.Entries.Count);
    }

    [Fact]
    public void Transfer_without_artifact_history_is_not_lost_by_file_action_filter()
    {
        var result = Sample();
        result.Devices[0].CopyIndications.Add(new CopyIndication
        { FileName = "report.txt", Direction = CopyDirection.ToDevice, Confidence = "High" });
        Assert.Empty(Context(result).DevicesWithActivity());
        Assert.Single(Context(result).Transfers());
    }

    [Fact]
    public void Same_model_different_instance_does_not_match_and_serial_prefix_is_not_an_identity()
    {
        var a = Sample().Devices[0];
        var b = new UsbDeviceRecord { DeviceInstanceId = a.DeviceInstanceId + "9", Serial = a.Serial + "9", FriendlyName = a.FriendlyName };
        var keys = DeviceLinkKeys.Build(a, [a, b]);
        var foreign = new EvidenceRecord { DeviceHint = b.DeviceInstanceId + " " + b.FriendlyName };
        Assert.Null(keys.Match(foreign));
        Assert.Equal("High", keys.Match(new EvidenceRecord { DeviceHint = a.DeviceInstanceId.Replace('\\', '#') })?.Confidence);
        Assert.Equal("High", keys.Match(new EvidenceRecord { RawText = JsonSerializer.Serialize(new { Device = a.DeviceInstanceId }) })?.Confidence);
    }

    [Fact]
    public void Media_risk_counts_physical_devices_not_usb_wpd_rows()
    {
        var result = Sample();
        result.Devices.Add(new UsbDeviceRecord
        {
            CanonicalDeviceId = result.Devices[0].CanonicalDeviceId,
            DeviceInstanceId = @"SWD\WPDBUSENUM\USBSTOR#SERIAL-12345678",
            DeviceKind = DeviceKindResolver.Storage
        });
        Assert.Equal(1, Assert.Single(MitreMapper.Map(result).Findings).EvidenceCount);
        result.Devices.Add(new UsbDeviceRecord { DeviceKind = DeviceKindResolver.Storage, CanonicalDeviceId = "OTHER" });
        Assert.Equal(2, Assert.Single(MitreMapper.Map(result).Findings).EvidenceCount);
    }

    [Fact]
    public void Missing_source_makes_summary_partial_even_without_free_text_warning()
    {
        var result = Sample();
        result.Coverage.Sources.Add(new SourceCoverage { Source = "OfflineHiveCollector", Status = "Error", Error = "Win32 206" });
        var summary = ScanCoverageSummary.From(result);
        Assert.True(summary.HasLimitations);
        Assert.Contains("OfflineHiveCollector", Assert.Single(summary.Details));
        Assert.All(KeyAnswersContent.Build(Context(result)), x => Assert.Contains("ограничениями", x.Note));
        Assert.False(ScanCoverageSummary.From(new AuditResult()).HasLimitations);
    }

    [Fact]
    public void Hive_family_copy_preserves_hive_logs_and_original_bytes()
    {
        var directory = Directory.CreateTempSubdirectory("ufa-copy-").FullName;
        try
        {
            var original = Path.Combine(directory, "оригинал.hiv");
            var copy = Path.Combine(directory, "копия.hiv");
            foreach (var suffix in new[] { "", ".LOG1", ".LOG2" }) File.WriteAllText(original + suffix, "bytes" + suffix);
            var outcome = LockedFileCopier.CopyHiveFamily(original, copy);
            Assert.True(outcome.Success, outcome.Error);
            foreach (var suffix in new[] { "", ".LOG1", ".LOG2" })
            {
                Assert.Equal("bytes" + suffix, File.ReadAllText(original + suffix));
                Assert.Equal(File.ReadAllBytes(original + suffix), File.ReadAllBytes(copy + suffix));
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void Registry_loader_preserves_unicode_long_path_and_rejects_live_root()
    {
        var path = Path.Combine(Path.GetTempPath(), new string('a', 100), new string('b', 100), "профиль", "NTUSER.DAT");
        Assert.StartsWith(@"\\?\", RegistryHiveCommands.ExtendedPath(path));
        Assert.EndsWith(@"профиль\NTUSER.DAT", RegistryHiveCommands.ExtendedPath(path));
        Assert.Throws<ArgumentException>(() => RegistryHiveCommands.Run("unload", @"HKLM\SYSTEM"));
        var result = RegistryHiveCommands.Run("load", @"HKU\UFA_TEST", path);
        Assert.Equal(2, result.ExitCode);
        Assert.Contains("Win32 2", result.Output);
        Assert.False(File.Exists(path));
    }

    private static AuditResult Sample() => new()
    {
        Devices = [new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_Kingston\SERIAL-12345678",
            Serial = "SERIAL-12345678", CanonicalDeviceId = "ONE", IsCanonicalPrimary = true,
            DeviceKind = DeviceKindResolver.Storage, VisualCategory = "RealUsb",
            FriendlyName = "Kingston DataTraveler", DriveLetters = "E:"
        }]
    };

    private static ForensicReportContext Context(AuditResult result) => ForensicReportContext.Create(
        result, policy: DevicePolicy.None, caseMetadata: new CaseMetadata(), usbExecutableHashes: []);
}
