using System.Text.Json;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class VolumeCacheRemovalTests
{
    private const string CachePath = @"HKLM\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\E:";
    private const string UsbId = @"USB\VID_05E3&PID_0751\5&393a40ce&0&7";

    [Fact]
    public async Task Selected_skwlkr_cache_is_removed_without_claiming_same_named_usb_or_other_drive()
    {
        var selected = Record();
        var otherCache = Record(CachePath.Replace("E:", "F:"));
        var usb = new UsbDeviceRecord { DeviceInstanceId = UsbId, FriendlyName = "SKWLKR", CanonicalDeviceId = "one" };
        selected.CanonicalDeviceId = otherCache.CanonicalDeviceId = "one";
        var world = new World();
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(Scan(selected, otherCache, usb), [selected]);

        var item = Assert.Single(plan.Items);
        Assert.True(item.CanRemove);
        Assert.Equal(DeviceTracePolicy.NormalizePath(CachePath), item.InstanceId);
        Assert.Empty(item.RelatedInstanceIds);
        Assert.Equal(selected.DeviceInstanceId, Assert.Single(plan.DatabaseRecords).DeviceInstanceId);

        var result = await service.ExecuteAsync(plan);
        Assert.Equal(1, result.RemovedCount);
        Assert.Equal(["backup", "delete:" + DeviceTracePolicy.NormalizePath(CachePath)], world.Actions);
        Assert.Equal(selected.DeviceInstanceId, Assert.Single(DeviceRemovalDatabaseSync.CompletedRecords(plan, result)));
    }

    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\E:\Properties")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\E")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\..")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\*: ")]
    public void Broad_or_non_drive_cache_paths_are_never_supported(string path)
    {
        Assert.False(DeviceTracePolicy.IsVolumeCachePath(path));
        Assert.Null(DeviceTracePolicy.NormalizePath(path));
    }

    [Fact]
    public void Binding_requires_own_cache_card_exact_source_and_collected_values()
    {
        var record = Record();
        Assert.NotNull(DeviceTracePolicy.Bind(CachePath, record, "hash"));
        record.DeviceType = "USB";
        Assert.Null(DeviceTracePolicy.Bind(CachePath, record, "hash"));
        record.DeviceType = "VolumeLabel";
        record.DeviceInstanceId = UsbId;
        Assert.Null(DeviceTracePolicy.Bind(CachePath, record, "hash"));
        record.DeviceInstanceId = CachePath;
        record.RawJson = JsonSerializer.Serialize(new { RegistryPath = CachePath });
        Assert.Null(DeviceTracePolicy.Bind(CachePath, record, "hash"));
        record.RawJson = JsonSerializer.Serialize(new { RegistryPath = CachePath.Replace("E:", "F:"), Values = Values() });
        Assert.Null(DeviceTracePolicy.Bind(CachePath, record, "hash"));
        record.RawJson = "invalid";
        Assert.Null(DeviceTracePolicy.Bind(CachePath, record, "hash"));
    }

    [Fact]
    public void Cache_snapshot_is_order_independent_but_all_values_and_types_are_checked()
    {
        var a = JsonSerializer.SerializeToElement(Values());
        var b = JsonSerializer.SerializeToElement(new Dictionary<string, object> { ["volumelabel"] = "SKWLKR", ["drivetype"] = 3 });
        Assert.Equal(DeviceTracePolicy.VolumeCacheValuesFingerprint(a), DeviceTracePolicy.VolumeCacheValuesFingerprint(b));
        var changed = JsonSerializer.SerializeToElement(new { DriveType = "3", VolumeLabel = "SKWLKR" });
        Assert.NotEqual(DeviceTracePolicy.VolumeCacheValuesFingerprint(a), DeviceTracePolicy.VolumeCacheValuesFingerprint(changed));
        using var invalid = JsonDocument.Parse("{\"VolumeLabel\":\"SKWLKR\",\"volumelabel\":\"another\"}");
        Assert.Empty(DeviceTracePolicy.VolumeCacheValuesFingerprint(invalid.RootElement));
        Assert.Empty(DeviceTracePolicy.VolumeCacheValuesFingerprint(JsonSerializer.SerializeToElement(new { DriveType = 3 })));
        Assert.Empty(DeviceTracePolicy.VolumeCacheValuesFingerprint(JsonSerializer.SerializeToElement(new object[0])));
    }

    [Fact]
    public void Conflicting_merged_snapshots_do_not_bind()
    {
        var record = Record();
        record.RawJson = JsonSerializer.Serialize(new
        {
            MergedRegistryEvidence = new[]
            {
                new { RegistryPath = CachePath, Values = Values() },
                new { RegistryPath = CachePath, Values = Values("other") }
            }
        });
        Assert.Null(DeviceTracePolicy.Bind(CachePath, record, "hash"));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Assigned_drive_or_changed_scan_snapshot_blocks_preview(bool assigned, bool changed)
    {
        var record = Record();
        var world = new World { DriveAssigned = assigned, CurrentValues = Values(changed ? "NEW_DEVICE" : "SKWLKR") };
        var item = Assert.Single(new DeviceRemovalService(world).Preview(Scan(record), [record]).Items);
        Assert.False(item.CanRemove);
        Assert.Contains(assigned ? "сейчас используется" : "со времени сканирования", item.Reason);
        Assert.Empty(world.Actions);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Drive_assignment_or_value_change_after_backup_cancels_cleanup(bool driveAssignment)
    {
        var record = Record();
        var world = new World();
        world.AfterBackup = () =>
        {
            world.DriveAssigned = driveAssignment;
            if (!driveAssignment)
            {
                world.CurrentValues = Values("NEW_DEVICE");
            }
        };
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(Scan(record), [record]);
        var result = await service.ExecuteAsync(plan);
        Assert.Equal("Blocked", Assert.Single(result.Items).Status);
        Assert.Equal(["backup"], world.Actions);
        Assert.Empty(DeviceRemovalDatabaseSync.CompletedRecords(plan, result));
    }

    [Fact]
    public void Forged_cache_trace_without_snapshot_is_protected()
    {
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(new(CachePath, "hash", []), [], _ => false));
        var trace = DeviceTracePolicy.Bind(CachePath, Record(), "hash")!;
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(trace with { DeviceIds = [UsbId] }, [], _ => false));
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(trace with { Vid = "05E3", Pid = "0751" }, [], _ => false));
        Assert.Equal("E:", DeviceTracePolicy.VolumeCacheDriveLetter(CachePath));
        Assert.Empty(DeviceTracePolicy.VolumeCacheDriveLetter(@"HKLM\SYSTEM"));
    }

    private static Dictionary<string, object> Values(string label = "SKWLKR") => new() { ["DriveType"] = 3, ["VolumeLabel"] = label };

    private static UsbDeviceRecord Record(string path = CachePath) => new()
    {
        DeviceInstanceId = path,
        DeviceType = "VolumeLabel",
        FriendlyName = "SKWLKR",
        RawJson = JsonSerializer.Serialize(new { RegistryPath = path, Values = Values() })
    };

    private static AuditResult Scan(params UsbDeviceRecord[] records)
    {
        var result = new AuditResult { ComputerName = "TEST", SessionId = "test" };
        result.Devices.AddRange(records);
        return result;
    }

    private sealed class World : IDeviceRemovalPlatform, IRegistryTracePlatform
    {
        public string ComputerName => "TEST";
        public List<string> Actions { get; } = [];
        public Dictionary<string, object> CurrentValues { get; set; } = Values();
        public bool DriveAssigned { get; set; }
        public string? Fingerprint { get; private set; } = "original";
        public Action? AfterBackup { get; set; }
        public IReadOnlyList<DeviceRemovalNode> ReadInventory() => [new(UsbId, "SKWLKR", false, Service: "USBSTOR")];
        public bool IsPresent(string id) => false;
        public bool InstanceExists(string id) => true;
        public void EnsureRemovalSupported() { }
        public string? ReadTraceFingerprint(string path) => Fingerprint;
        public string GetTraceProtectionReason(DeviceRegistryTrace trace) => WindowsDeviceRemovalPlatform.VolumeCacheProtectionReason(
            trace, DeviceTracePolicy.VolumeCacheValuesFingerprint(JsonSerializer.SerializeToElement(CurrentValues)), DriveAssigned);
        public Task<string> BackupAsync(DeviceRemovalPlan plan, CancellationToken cancellationToken)
        {
            Actions.Add("backup");
            AfterBackup?.Invoke();
            return Task.FromResult("backup");
        }
        public Task<DeviceRemovalCommandResult> RemoveAsync(string id) => throw new InvalidOperationException("An unrelated PnP device must not be removed.");
        public Task<DeviceRemovalCommandResult> RemoveTraceAsync(DeviceRegistryTrace trace)
        {
            Assert.Equal(DeviceTracePolicy.NormalizePath(CachePath), trace.RegistryPath);
            Actions.Add("delete:" + trace.RegistryPath);
            Fingerprint = null;
            return Task.FromResult(new DeviceRemovalCommandResult(0, ""));
        }
        public Task SaveResultAsync(string directory, DeviceRemovalResult result) => Task.CompletedTask;
    }
}
