using System.Text.Json;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class DeviceRemovalRegressionTests
{
    private const string Disk = @"USBSTOR\DISK&VEN_GENERIC&PROD_STORAGE_DEVICE&REV_1404\6&1234ABCD&0";
    private const string GuidSuffix = "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
    private static string Wrapper(string prefix, string disk = Disk) => prefix + @"\_??_" + disk.Replace('\\', '#') + "#" + GuidSuffix;
    private static string Portable(string disk = Disk) => @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices\"
        + Wrapper(@"SWD\WPDBUSENUM", disk).Replace('\\', '#');
    private static UsbDeviceRecord Record(string id, string path = "") => new()
    {
        DeviceInstanceId = id,
        RawJson = JsonSerializer.Serialize(new { RegistryPath = path })
    };
    private static AuditResult Scan(params UsbDeviceRecord[] records)
    {
        var result = new AuditResult { ComputerName = "TEST", SessionId = "test" };
        result.Devices.AddRange(records);
        return result;
    }

    [Theory]
    [InlineData("SKWLKR")]
    [InlineData("USB Drive")]
    [InlineData("Телефон")]
    public async Task Orphan_wpd_without_vid_pid_includes_exact_volume_and_history_but_not_same_named_device(string name)
    {
        var selected = Record(@"SWD\WPDBUSENUM\_??_" + Disk, Portable());
        selected.FriendlyName = name;
        var unrelated = Record(@"SWD\WPDBUSENUM\_??_" + Disk.Replace("1234ABCD", "9999ABCD"), Portable(Disk.Replace("1234ABCD", "9999ABCD")));
        unrelated.FriendlyName = name;
        var world = new World();
        var volume = Wrapper(@"STORAGE\Volume");
        world.Nodes.Add(new(volume, name, false, Service: "volume"));
        world.Traces.Add(Portable(), "original");
        world.Traces.Add(Portable(Disk.Replace("1234ABCD", "9999ABCD")), "other");
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(Scan(selected, unrelated), [selected]);
        Assert.Equal(2, plan.RemovableCount);
        Assert.Equal(0, plan.ProtectedCount);
        Assert.Single(plan.DatabaseRecords);
        var result = await service.ExecuteAsync(plan);
        Assert.Equal(2, result.RemovedCount);
        Assert.Equal([selected.DeviceInstanceId], DeviceRemovalDatabaseSync.CompletedRecords(plan, result));
        Assert.Equal("other", Assert.Single(world.Traces).Value);
        Assert.Empty(world.Nodes);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(null)]
    public void Connected_or_unknown_volume_protects_its_orphan_wpd_history(bool? present)
    {
        var selected = Record(@"SWD\WPDBUSENUM\_??_" + Disk, Portable());
        var world = new World();
        world.Nodes.Add(new(Wrapper(@"STORAGE\Volume"), "Volume", present, Service: "volume"));
        world.Traces.Add(Portable(), "original");
        var plan = new DeviceRemovalService(world).Preview(Scan(selected), [selected]);
        Assert.Equal(0, plan.RemovableCount);
        Assert.Equal(2, plan.ProtectedCount);
    }

    [Fact]
    public async Task Phone_selection_includes_pnp_components_and_their_independent_historical_records()
    {
        const string parent = @"USB\VID_22D9&PID_2764\PHONE-123";
        const string child = @"USB\VID_22D9&PID_2764&MI_00\6&1234ABCD&0&0000";
        var selected = Record(parent);
        var historyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices\" + child.Replace('\\', '#');
        var history = Record(child, historyPath);
        var world = new World();
        world.Nodes.Add(new(parent, "Phone", false, Service: "usbccgp", ParentIdPrefix: "6&1234ABCD&0"));
        world.Nodes.Add(new(child, "MTP", false, Service: "WUDFRd"));
        world.Traces.Add(historyPath, "original");
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(Scan(selected, history), [selected]);
        Assert.Equal(3, plan.RemovableCount);
        Assert.Equal(2, plan.DatabaseRecords.Count);
        var result = await service.ExecuteAsync(plan);
        Assert.Equal(3, result.RemovedCount);
        Assert.Equal(2, DeviceRemovalDatabaseSync.CompletedRecords(plan, result).Count);
        Assert.Empty(world.Traces);
        Assert.Empty(world.Nodes);
    }

    [Theory]
    [InlineData(@"USB\VID_1234&PID_5678\SERIAL-A")]
    [InlineData(Disk)]
    [InlineData(@"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_Test#SERIAL-A&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}")]
    public async Task Inactive_control_set_is_backed_up_and_removed_while_active_enum_uses_pnp(string id)
    {
        var inactive = @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Enum\" + id;
        var active = @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\" + id;
        var selected = Record(id);
        selected.RawJson = JsonSerializer.Serialize(new { RegistryPaths = new[] { active, inactive } });
        var world = new World();
        world.Nodes.Add(new(id, "Device", false, Service: "USBSTOR"));
        world.Traces.Add(inactive, "original");
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(Scan(selected), [selected]);
        Assert.Equal(2, plan.RemovableCount);
        Assert.DoesNotContain(plan.Items, x => x.InstanceId == active);
        var result = await service.ExecuteAsync(plan);
        Assert.Equal(2, result.RemovedCount);
        Assert.Equal("backup", world.Actions[0]);
        Assert.Contains("trace:" + inactive, world.Actions);
    }

    [Fact]
    public async Task Changing_active_control_set_after_backup_blocks_direct_enum_deletion()
    {
        var path = @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Enum\" + Disk;
        var selected = Record(Disk, path);
        var world = new World();
        world.Traces.Add(path, "original");
        world.AfterBackup = () => world.Current = 2;
        var service = new DeviceRemovalService(world);
        var result = await service.ExecuteAsync(service.Preview(Scan(selected), [selected]));
        Assert.Equal("Blocked", Assert.Single(result.Items).Status);
        Assert.Equal(["backup"], world.Actions);
        Assert.Single(world.Traces);
    }

    [Fact]
    public void Legacy_doubled_wpd_path_is_repaired_without_allowing_arbitrary_subkeys()
    {
        var id = Wrapper(@"SWD\WPDBUSENUM");
        var expected = @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Enum\" + id;
        var record = Record(id, expected + @"\" + id.Split('\\')[2]);
        Assert.Equal(expected, Assert.Single(DeviceTracePolicy.SourcePaths(record)));
        Assert.Equal(id, DeviceTracePolicy.EnumInstanceId(expected));
        Assert.Null(DeviceTracePolicy.NormalizePath(expected + @"\Properties"));
        Assert.Null(DeviceTracePolicy.NormalizePath(expected + @"\*"));
        Assert.Null(DeviceTracePolicy.NormalizePath(@"HKLM\SYSTEM\ControlSet002\Enum\USB"));
    }

    [Fact]
    public void Orphan_internal_scsi_record_cannot_be_treated_as_usb_history()
    {
        const string id = @"SCSI\DISK&VEN_NVME&PROD_INTERNAL\5&1234&0";
        var path = @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Enum\" + id;
        var record = Record(id, path);
        var world = new World();
        world.Traces.Add(path, "original");
        var plan = new DeviceRemovalService(world).Preview(Scan(record), [record]);
        Assert.False(Assert.Single(plan.Items).CanRemove);
        Assert.Contains("USB", plan.Items[0].Reason);
    }

    [Fact]
    public void Volume_whose_backing_device_is_internal_remains_protected()
    {
        var volume = Wrapper(@"STORAGE\Volume", @"SCSI\DISK&VEN_NVME&PROD_INTERNAL\5&1234&0");
        Assert.False(DeviceRemovalPolicy.IsUsbVolume(volume));
        Assert.False(DeviceRemovalPolicy.IsInstanceId(volume));
    }

    [Fact]
    public async Task Successful_subset_is_reported_as_partial_when_preview_has_protected_records()
    {
        var selected = Record(Disk, Portable());
        var unsupported = Record(@"HKLM\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\E:");
        unsupported.DeviceType = "VolumeLabel";
        var world = new World();
        world.Traces.Add(Portable(), "original");
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(Scan(selected, unsupported), [selected, unsupported]);
        var result = await service.ExecuteAsync(plan);
        Assert.Equal(1, result.RemovedCount);
        Assert.Equal(1, result.SkippedCount);
        Assert.Contains("не полностью", result.Summary);
        Assert.Contains("Общий кэш", plan.Items.Single(x => !x.CanRemove).Reason);
    }

    [Fact]
    public void Inactive_hub_history_remains_protected_after_the_live_node_disappears()
    {
        const string id = @"USB\VID_1234&PID_5678\HUB";
        var path = @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Enum\" + id;
        var record = Record(id, path);
        record.Service = "USBHUB3";
        var world = new World();
        world.Traces.Add(path, "original");
        var item = Assert.Single(new DeviceRemovalService(world).Preview(Scan(record), [record]).Items);
        Assert.False(item.CanRemove);
        Assert.Contains("инфраструктуре", item.Reason);
    }

    [Fact]
    public void Unbound_existing_history_is_reported_and_prevents_database_card_removal()
    {
        var wrongPath = Portable(Disk.Replace("1234ABCD", "9999ABCD"));
        var record = Record(Disk, wrongPath);
        var world = new World();
        world.Nodes.Add(new(Disk, "Disk", false, Service: "disk"));
        world.Traces.Add(wrongPath, "original");
        var plan = new DeviceRemovalService(world).Preview(Scan(record), [record]);
        Assert.Equal(1, plan.RemovableCount);
        Assert.Equal(1, plan.ProtectedCount);
        Assert.Empty(DeviceRemovalDatabaseSync.CompletedRecords(plan, new("backup", [new(Disk, "", "Removed", "")])));
    }

    private sealed class World : IDeviceRemovalPlatform, IRegistryTracePlatform
    {
        public string ComputerName => "TEST";
        public int Current { get; set; } = 1;
        public List<DeviceRemovalNode> Nodes { get; } = [];
        public Dictionary<string, string> Traces { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Actions { get; } = [];
        public Action? AfterBackup { get; set; }
        public bool IsActiveEnumPath(string path) => WindowsDeviceRemovalPlatform.IsActiveEnumPath(path, Current);
        public string? ReadTraceFingerprint(string path) => Traces.GetValueOrDefault(path);
        public IReadOnlyList<DeviceRemovalNode> ReadInventory() => Nodes.ToArray();
        public bool IsPresent(string id) => Nodes.Any(x => x.InstanceId == id && x.Present == true);
        public bool InstanceExists(string id) => Nodes.Any(x => x.InstanceId == id);
        public void EnsureRemovalSupported() { }
        public Task<string> BackupAsync(DeviceRemovalPlan plan, CancellationToken cancellationToken)
        {
            Actions.Add("backup");
            AfterBackup?.Invoke();
            return Task.FromResult("backup");
        }
        public Task<DeviceRemovalCommandResult> RemoveAsync(string id)
        {
            Actions.Add("pnp:" + id);
            Nodes.RemoveAll(x => x.InstanceId == id);
            return Task.FromResult(new DeviceRemovalCommandResult(0, ""));
        }
        public Task<DeviceRemovalCommandResult> RemoveTraceAsync(DeviceRegistryTrace trace)
        {
            Actions.Add("trace:" + trace.RegistryPath);
            Traces.Remove(trace.RegistryPath);
            return Task.FromResult(new DeviceRemovalCommandResult(0, ""));
        }
        public Task SaveResultAsync(string directory, DeviceRemovalResult result) => Task.CompletedTask;
    }
}
