using System.IO;
using System.Text;
using System.Text.Json;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class MountedDeviceRemovalTests
{
    private const string Disk = @"USBSTOR\Disk&Ven_Generic&Prod_STORAGE_DEVICE&Rev_1404\6&2cb3244f&1";
    private const string ValueName = @"\??\Volume{97bc3a52-b99e-11f1-989c-9010576eda10}";
    private const string Path = @"HKLM\SYSTEM\MountedDevices\" + ValueName;
    private static byte[] Data(string disk = Disk) => Encoding.Unicode.GetBytes("_??_" + disk.Replace('\\', '#') + "#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}");
    private static UsbDeviceRecord Record(string path = Path, string disk = Disk) => new()
    {
        DeviceInstanceId = path,
        DeviceType = "VolumeMapping",
        RawJson = JsonSerializer.Serialize(new { MappingName = DeviceTracePolicy.MountedValueName(path), RawBinaryBase64 = Convert.ToBase64String(Data(disk)) })
    };
    private static AuditResult Scan(params UsbDeviceRecord[] records)
    {
        var scan = new AuditResult { ComputerName = "TEST", SessionId = "test" };
        scan.Devices.AddRange(records);
        return scan;
    }

    [Fact]
    public async Task Selecting_usb_adds_only_exact_mappings_then_cleans_database_after_both_succeed()
    {
        var disk = new UsbDeviceRecord { DeviceInstanceId = Disk, FriendlyName = "SKWLKR" };
        var mapping = Record();
        var other = Record(Path.Replace("97bc3a52", "97bc3a53"), Disk.Replace("&1", "&2"));
        var world = new World();
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(Scan(disk, mapping, other), [disk]);
        Assert.Equal(2, plan.RemovableCount);
        Assert.Equal(2, plan.DatabaseRecords.Count);
        Assert.DoesNotContain(plan.Items, x => x.InstanceId == DeviceTracePolicy.NormalizePath(other.DeviceInstanceId));
        var result = await service.ExecuteAsync(plan);
        Assert.Equal(2, result.RemovedCount);
        Assert.Equal(["backup", "value", "pnp"], world.Actions);
        Assert.Equal(2, DeviceRemovalDatabaseSync.CompletedRecords(plan, result).Count);
    }

    [Fact]
    public async Task Changed_value_after_backup_is_preserved_and_database_card_remains()
    {
        var record = Record();
        var world = new World();
        world.AfterBackup = () => world.Bytes = Data(Disk.Replace("&1", "&2"));
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(Scan(record), [record]);
        var result = await service.ExecuteAsync(plan);
        Assert.Equal("Blocked", Assert.Single(result.Items).Status);
        Assert.Equal(["backup"], world.Actions);
        Assert.Empty(DeviceRemovalDatabaseSync.CompletedRecords(plan, result));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Connected_device_or_assigned_volume_blocks_value_cleanup(bool connected, bool volumeAssigned)
    {
        var record = Record();
        var world = new World { Connected = connected, VolumeAssigned = volumeAssigned };
        Assert.False(Assert.Single(new DeviceRemovalService(world).Preview(Scan(record), [record]).Items).CanRemove);
    }

    [Fact]
    public void Changed_snapshot_missing_usb_proof_and_unrelated_paths_are_rejected()
    {
        var record = Record();
        var trace = DeviceTracePolicy.Bind(Path, record, DeviceTracePolicy.MountedFingerprint(Data()))!;
        Assert.Empty(DeviceTracePolicy.ProtectionReason(trace, [], _ => false));
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(trace with { Fingerprint = "changed" }, [], _ => false));
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(trace with { DeviceIds = [Disk + "other"] }, [], _ => false));
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(trace with { MountedValueSnapshot = "invalid" }, [], _ => false));
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(trace with { MountedValueSnapshot = "AQIDBA==" }, [], _ => false));
        Assert.Null(DeviceTracePolicy.NormalizePath(@"HKLM\SYSTEM\MountedDevices"));
        Assert.Null(DeviceTracePolicy.NormalizePath(Path + @"\Properties"));
        Assert.Throws<ArgumentException>(() => RegistryTraceAccess.ValidatePath(Path, true));
        record.RawJson = "invalid";
        Assert.Null(DeviceTracePolicy.Bind(Path, record, "hash"));
        record = Record(disk: @"SCSI\Disk&Ven_NVME\INTERNAL");
        Assert.Null(DeviceTracePolicy.Bind(Path, record, "hash"));
    }

    [Fact]
    public async Task Backup_contains_only_selected_value_and_detects_changes_during_backup()
    {
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "UsbForensicAudit-mounted-" + Guid.NewGuid().ToString("N"));
        try
        {
            var record = Record();
            var fingerprint = DeviceTracePolicy.MountedFingerprint(Data());
            var trace = DeviceTracePolicy.Bind(Path, record, fingerprint)!;
            var plan = new DeviceRemovalPlan("TEST", "test", DateTimeOffset.UtcNow,
                [new(trace.RegistryPath, "SKWLKR mapping", true, "", null, trace.DeviceIds, trace)]);
            var platform = new WindowsDeviceRemovalPlatform(directory, _ => false, _ => false,
                (_, _, _) => throw new Exception("Do not export or delete MountedDevices root"), () => { }, _ => fingerprint,
                saveRegistryKey: (_, _) => throw new Exception("Do not save whole MountedDevices"));
            var backup = await platform.BackupAsync(plan, CancellationToken.None);
            var export = await File.ReadAllTextAsync(System.IO.Path.Combine(backup, "device-0001.reg"));
            Assert.Contains(ValueName.Replace("\\", "\\\\", StringComparison.Ordinal), export);
            Assert.DoesNotContain("DosDevices", export);
            fingerprint = "changed";
            await Assert.ThrowsAsync<IOException>(() => platform.BackupAsync(plan, CancellationToken.None));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private sealed class World : IDeviceRemovalPlatform, IRegistryTracePlatform
    {
        public string ComputerName => "TEST";
        public byte[]? Bytes { get; set; } = Data();
        public bool Connected { get; set; }
        public bool VolumeAssigned { get; set; }
        private bool _exists = true;
        public List<string> Actions { get; } = [];
        public Action? AfterBackup { get; set; }
        public IReadOnlyList<DeviceRemovalNode> ReadInventory() => _exists ? [new(Disk, "SKWLKR", Connected, Service: "disk")] : [];
        public bool IsPresent(string id) => Connected && id == Disk;
        public bool InstanceExists(string id) => _exists && id == Disk;
        public void EnsureRemovalSupported() { }
        public string? ReadTraceFingerprint(string path) => Bytes is { } bytes ? DeviceTracePolicy.MountedFingerprint(bytes) : null;
        public string GetTraceProtectionReason(DeviceRegistryTrace trace) => VolumeAssigned ? "Том используется" : "";
        public Task<string> BackupAsync(DeviceRemovalPlan plan, CancellationToken token) { Actions.Add("backup"); AfterBackup?.Invoke(); return Task.FromResult("backup"); }
        public Task<DeviceRemovalCommandResult> RemoveAsync(string id) { Actions.Add("pnp"); _exists = false; return Task.FromResult(new DeviceRemovalCommandResult(0, "")); }
        public Task<DeviceRemovalCommandResult> RemoveTraceAsync(DeviceRegistryTrace trace) { Actions.Add("value"); Bytes = null; return Task.FromResult(new DeviceRemovalCommandResult(0, "")); }
        public Task SaveResultAsync(string directory, DeviceRemovalResult result) => Task.CompletedTask;
    }
}
