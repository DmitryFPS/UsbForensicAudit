using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class DatabaseDeviceRemovalTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "UsbForensicAudit-delete-test-" + Guid.NewGuid().ToString("N"));
    private const string Id = @"USB\VID_1234&PID_5678\SERIAL-A";
    private static AuditResult Scan(string session = "one")
    {
        var scan = new AuditResult { SessionId = session, ComputerName = "TEST" };
        scan.Devices.Add(new() { DeviceInstanceId = Id, Source = "Registry: USB", FriendlyName = "Selected" });
        scan.Devices.Add(new() { DeviceInstanceId = Id + "-OTHER", FriendlyName = "Other device" });
        return scan;
    }

    [Fact]
    public void Removal_persists_on_reload_backs_up_records_and_preserves_other_sessions_and_archive()
    {
        var storage = new AuditStorage(_directory);
        storage.Save(Scan());
        storage.Save(Scan("two"));
        var journal = File.ReadAllBytes(storage.JsonlPath);
        var result = storage.DeleteDeviceRecords("one", [Id.ToLowerInvariant()]);
        Assert.Equal(1, result.RemovedCount);
        var backup = Path.Combine(result.BackupDirectory, "devices.json");
        using var copy = JsonDocument.Parse(File.ReadAllText(backup));
        Assert.Equal(Id, copy.RootElement.GetProperty("Records")[0].GetProperty("DeviceInstanceId").GetString());
        Assert.Equal(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(backup))),
            File.ReadAllText(Path.Combine(result.BackupDirectory, "sha256.txt")));
        var reopened = new AuditStorage(_directory);
        Assert.Equal(Id + "-OTHER", Assert.Single(reopened.Load("one")!.Devices).DeviceInstanceId);
        Assert.Equal(2, reopened.Load("two")!.Devices.Count);
        Assert.Equal(journal, File.ReadAllBytes(storage.JsonlPath));
        Assert.True(new EvidenceIntegrityVerifier(storage).Verify().IsIntact);
        Assert.Equal(1, storage.ListSessions().Single(x => x.SessionId == "one").DeviceCount);
        storage.Save(Scan());
        Assert.Single(storage.Load("one")!.Devices);
    }

    [Fact]
    public void Failed_backup_leaves_database_intact()
    {
        var storage = new AuditStorage(_directory);
        storage.Save(Scan());
        File.WriteAllText(Path.Combine(_directory, "database-removal"), "blocks directory creation");
        Assert.ThrowsAny<IOException>(() => storage.DeleteDeviceRecords("one", [Id]));
        Assert.Equal(2, storage.Load("one")!.Devices.Count);
    }

    [Fact]
    public void Empty_selection_is_rejected_and_absent_selection_does_not_delete_anything()
    {
        var storage = new AuditStorage(_directory);
        storage.Save(Scan());
        Assert.Throws<ArgumentException>(() => storage.DeleteDeviceRecords("one", []));
        Assert.Throws<ArgumentException>(() => storage.DeleteDeviceRecords("", [Id]));
        Assert.Throws<ArgumentException>(() => storage.DeleteDeviceRecords("one", [""]));
        Assert.Equal(0, storage.DeleteDeviceRecords("unknown-session", [Id]).RemovedCount);
        Assert.Equal(0, storage.DeleteDeviceRecords("one", ["' OR 1=1 --"]).RemovedCount);
        Assert.Equal(2, storage.Load("one")!.Devices.Count);
        Assert.False(Directory.Exists(Path.Combine(_directory, "database-removal")));
    }

    [Fact]
    public void All_sources_of_selected_instance_are_removed_but_same_model_is_retained()
    {
        var storage = new AuditStorage(_directory);
        var scan = Scan();
        scan.Devices.Add(new() { DeviceInstanceId = Id, Source = "Registry: DeviceClasses" });
        storage.Save(scan);
        Assert.Equal(2, storage.DeleteDeviceRecords("one", [Id, Id]).RemovedCount);
        Assert.Equal(Id + "-OTHER", Assert.Single(storage.Load("one")!.Devices).DeviceInstanceId);
        Assert.Equal(0, storage.DeleteDeviceRecords("one", [Id]).RemovedCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Successful_windows_removal_automatically_deletes_only_selected_database_records(bool alreadyAbsent)
    {
        var storage = new AuditStorage(_directory);
        var scan = Scan();
        storage.Save(scan);
        var platform = new RemovalPlatform(scan);
        var service = new DeviceRemovalService(platform, storage);
        var plan = service.Preview(scan, [scan.Devices[0]]);
        if (alreadyAbsent)
        {
            platform.Nodes.RemoveAt(0);
        }

        var result = await service.ExecuteAsync(plan);
        Assert.Equal(1, result.RemovedCount + result.AbsentCount);
        Assert.Equal(1, result.DatabaseRemoval!.RemovedCount);
        Assert.Equal(Id + "-OTHER", Assert.Single(storage.Load("one")!.Devices).DeviceInstanceId);
        Assert.Equal(result, platform.SavedResults.Last());
        Assert.Contains("Удалено карточек из базы: 1", result.Summary);
    }

    [Fact]
    public async Task Partial_windows_failure_keeps_failed_record_in_database()
    {
        var storage = new AuditStorage(_directory);
        var scan = Scan();
        storage.Save(scan);
        var platform = new RemovalPlatform(scan) { FailedId = Id + "-OTHER" };
        var service = new DeviceRemovalService(platform, storage);
        var result = await service.ExecuteAsync(service.Preview(scan, scan.Devices));
        Assert.Equal(1, result.RemovedCount);
        Assert.Equal(1, result.FailedCount);
        Assert.Equal(1, result.DatabaseRemoval!.RemovedCount);
        Assert.Equal(Id + "-OTHER", Assert.Single(storage.Load("one")!.Devices).DeviceInstanceId);
    }

    [Fact]
    public async Task Partly_removed_canonical_device_keeps_all_its_database_records()
    {
        var storage = new AuditStorage(_directory);
        var scan = Scan();
        foreach (var record in scan.Devices)
        {
            record.CanonicalDeviceId = "same-physical-device";
        }

        storage.Save(scan);
        var platform = new RemovalPlatform(scan) { FailedId = Id + "-OTHER" };
        var service = new DeviceRemovalService(platform, storage);
        var result = await service.ExecuteAsync(service.Preview(scan, [scan.Devices[0]]));
        Assert.Equal(1, result.RemovedCount);
        Assert.Equal(1, result.FailedCount);
        Assert.Equal(0, result.DatabaseRemoval!.RemovedCount);
        Assert.Equal(2, storage.Load("one")!.Devices.Count);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Backup_failure_or_cancellation_keeps_database_intact(bool backupFailure)
    {
        var storage = new AuditStorage(_directory);
        var scan = Scan();
        storage.Save(scan);
        using var cancellation = new CancellationTokenSource();
        var platform = new RemovalPlatform(scan)
        {
            FailBackup = backupFailure,
            AfterBackup = backupFailure ? null : cancellation.Cancel
        };
        var service = new DeviceRemovalService(platform, storage);
        var plan = service.Preview(scan, scan.Devices);
        if (backupFailure)
        {
            await Assert.ThrowsAsync<IOException>(() => service.ExecuteAsync(plan));
        }
        else
        {
            var result = await service.ExecuteAsync(plan, cancellationToken: cancellation.Token);
            Assert.All(result.Items, item => Assert.Equal("Cancelled", item.Status));
            Assert.Equal(0, result.DatabaseRemoval!.RemovedCount);
        }
        Assert.Equal(2, storage.Load("one")!.Devices.Count);
        Assert.Empty(platform.Removed);
    }

    [Fact]
    public async Task Database_backup_failure_reports_windows_success_and_preserves_cards()
    {
        var storage = new AuditStorage(_directory);
        var scan = Scan();
        storage.Save(scan);
        File.WriteAllText(Path.Combine(_directory, "database-removal"), "blocks directory creation");
        var platform = new RemovalPlatform(scan);
        var service = new DeviceRemovalService(platform, storage);
        var result = await service.ExecuteAsync(service.Preview(scan, [scan.Devices[0]]));
        Assert.Equal(1, result.RemovedCount);
        Assert.NotEmpty(result.DatabaseError);
        Assert.Contains("Не удалось обновить базу", result.Summary);
        Assert.Equal(2, storage.Load("one")!.Devices.Count);
        Assert.Equal(result, platform.SavedResults.Last());
    }

    [Fact]
    public async Task Protocol_failure_stops_further_windows_changes_but_syncs_completed_removal()
    {
        var storage = new AuditStorage(_directory);
        var scan = Scan();
        storage.Save(scan);
        var platform = new RemovalPlatform(scan) { FailSaveResult = true };
        var service = new DeviceRemovalService(platform, storage);
        var result = await service.ExecuteAsync(service.Preview(scan, scan.Devices));
        Assert.Equal(1, result.RemovedCount);
        Assert.Equal("NotAttempted", result.Items[1].Status);
        Assert.Single(platform.Removed);
        Assert.Equal(1, result.DatabaseRemoval!.RemovedCount);
        Assert.Contains("Не удалось сохранить протокол", result.Summary);
        Assert.Equal(Id + "-OTHER", Assert.Single(storage.Load("one")!.Devices).DeviceInstanceId);
    }

    [Fact]
    public void Preview_includes_other_sources_with_the_same_exact_id_before_deleting_database_records()
    {
        var scan = Scan();
        scan.Devices.Add(new() { DeviceInstanceId = Id.ToLowerInvariant(), IdentityAliases = [Id + "-CHILD"] });
        var platform = new RemovalPlatform(scan);
        platform.Nodes.Add(new(Id + "-CHILD", "Child", false, Service: "USBSTOR"));
        var plan = new DeviceRemovalService(platform).Preview(scan, [scan.Devices[0]]);
        Assert.Equal(2, plan.RemovableCount);
        Assert.All(plan.DatabaseRecords, record => Assert.Equal(2, record.TargetIds.Count));
        var partial = new DeviceRemovalResult("backup", [new(Id, "", "Removed", "")]);
        Assert.Empty(DeviceRemovalDatabaseSync.CompletedRecords(plan, partial));
    }

    [Theory]
    [InlineData("Removed", true, true)]
    [InlineData("AlreadyAbsent", true, true)]
    [InlineData("Failed", true, false)]
    [InlineData("Cancelled", true, false)]
    [InlineData("Blocked", true, false)]
    [InlineData("Removed", false, false)]
    public void Database_sync_uses_trace_to_card_mapping_and_requires_confirmed_success(string status, bool allowed, bool deleted)
    {
        const string path = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices\USB#VID_1234&PID_5678#SERIAL-A";
        var plan = new DeviceRemovalPlan("TEST", "one", DateTimeOffset.UtcNow,
            [new(path, "History", allowed, "", null, [])])
        {
            DatabaseRecords = [new(Id, [path]), new("unknown", ["missing-target"]), new("empty", [])]
        };
        var result = new DeviceRemovalResult("backup", [new(path.ToLowerInvariant(), "History", status, "")]);
        var completed = DeviceRemovalDatabaseSync.CompletedRecords(plan, result);
        Assert.Equal(deleted ? new[] { Id } : [], completed);
        Assert.Empty(DeviceRemovalDatabaseSync.CompletedRecords(plan, new("backup", [])));
        Assert.Empty(DeviceRemovalDatabaseSync.CompletedRecords(plan,
            new("backup", [new(path, "", "Removed", ""), new(path, "", "Failed", "")])));
    }

    private sealed class RemovalPlatform(AuditResult scan) : IDeviceRemovalPlatform
    {
        public string ComputerName => "TEST";
        public List<DeviceRemovalNode> Nodes { get; } = scan.Devices.DistinctBy(x => x.DeviceInstanceId, StringComparer.OrdinalIgnoreCase)
            .Select(x => new DeviceRemovalNode(x.DeviceInstanceId, x.DisplayName, false, Service: "USBSTOR")).ToList();
        public List<string> Removed { get; } = [];
        public List<DeviceRemovalResult> SavedResults { get; } = [];
        public string FailedId { get; init; } = "";
        public bool FailBackup { get; init; }
        public bool FailSaveResult { get; init; }
        public Action? AfterBackup { get; init; }
        public IReadOnlyList<DeviceRemovalNode> ReadInventory() => Nodes.ToArray();
        public bool IsPresent(string instanceId) => false;
        public bool InstanceExists(string instanceId) => Nodes.Any(x => x.InstanceId == instanceId);
        public void EnsureRemovalSupported() { }
        public Task<string> BackupAsync(DeviceRemovalPlan plan, CancellationToken cancellationToken)
        {
            if (FailBackup)
            {
                throw new IOException("Backup failed");
            }

            AfterBackup?.Invoke();
            return Task.FromResult("test-backup");
        }
        public Task<DeviceRemovalCommandResult> RemoveAsync(string instanceId)
        {
            if (instanceId == FailedId)
            {
                return Task.FromResult(new DeviceRemovalCommandResult(5, "Access denied"));
            }

            Nodes.RemoveAll(x => x.InstanceId == instanceId);
            Removed.Add(instanceId);
            return Task.FromResult(new DeviceRemovalCommandResult(0, ""));
        }
        public Task SaveResultAsync(string backupDirectory, DeviceRemovalResult result)
        {
            if (FailSaveResult)
            {
                throw new IOException("Protocol write failed");
            }

            SavedResults.Add(result);
            return Task.CompletedTask;
        }
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
