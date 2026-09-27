using System.IO;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceRemovalTests
{
    private const string Id = @"USB\VID_1234&PID_5678\SERIAL-A";
    private const string OtherId = @"USB\VID_1234&PID_5678\SERIAL-B";
    private static DeviceRemovalNode Node(string id = Id, bool? present = false, string container = "") =>
        new(id, id, present, container, "USBSTOR");
    private static AuditResult Scan(params UsbDeviceRecord[] devices)
    {
        var scan = new AuditResult { ComputerName = "TEST-PC", SessionId = "test" };
        scan.Devices.AddRange(devices);
        return scan;
    }
    private static UsbDeviceRecord Record(string id = Id, string canonical = "") =>
        new() { DeviceInstanceId = id, CanonicalDeviceId = canonical };

    [Fact]
    public void Preview_of_one_model_instance_does_not_select_another_with_same_vid_pid()
    {
        var selected = Record();
        var platform = new FakePlatform(Node(), Node(OtherId));
        var plan = new DeviceRemovalService(platform).Preview(Scan(selected, Record(OtherId)), [selected]);
        Assert.Equal(Id, Assert.Single(plan.Items).InstanceId);
        Assert.Equal(1, plan.RemovableCount);
        Assert.Empty(platform.Removed);
        Assert.Equal(0, platform.Backups);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(null)]
    public void Present_or_unknown_component_blocks_the_whole_related_device(bool? present)
    {
        const string container = "{1352bcbf-4624-43b3-9d1f-dea941d249a0}";
        var record = Record();
        var platform = new FakePlatform(Node(container: container), Node(OtherId, present, container));
        var plan = new DeviceRemovalService(platform).Preview(Scan(record), [record]);
        Assert.Equal(0, plan.RemovableCount);
        Assert.Equal(1, plan.ProtectedCount);
    }

    [Fact]
    public void Related_component_check_follows_composite_grandchildren()
    {
        var parent = Node() with { ParentIdPrefix = "6&1234&0" };
        var child = Node(@"USB\VID_1234&PID_5678&MI_00\6&1234&0&0000") with { ParentIdPrefix = "7&2345&0" };
        var grandchild = Node(@"HID\VID_1234&PID_5678\7&2345&0&0000", true);
        var family = DeviceRemovalPolicy.Related(parent, [parent, child, grandchild]);
        Assert.Equal(3, family.Count);
        Assert.Contains("подключены", DeviceRemovalPolicy.ProtectionReason(parent, family));
    }

    [Theory]
    [InlineData(@"{00000000-0000-0000-0000-000000000000}")]
    [InlineData(@"{00000000-0000-0000-ffff-ffffffffffff}")]
    [InlineData("not-a-guid")]
    public void Placeholder_containers_do_not_link_unrelated_devices(string container)
    {
        var node = Node(container: container);
        Assert.Single(DeviceRemovalPolicy.Related(node, [node, Node(OtherId, true, container)]));
    }

    [Theory]
    [InlineData(@"USB\ROOT_HUB30\4&TEST&0", "USBHUB3")]
    [InlineData(@"USB\VID_1234&PID_5678\HUB", "USBHUB")]
    [InlineData(@"SCSI\Disk&Ven_NVMe&Prod_Internal\1", "disk")]
    [InlineData(@"SWD\DRIVERENUM\THUNDERBOLT", "nhi")]
    public void Infrastructure_and_unrelated_internal_storage_are_protected(string id, string service)
    {
        var record = Record(id);
        var platform = new FakePlatform(Node(id) with { Service = service });
        var plan = new DeviceRemovalService(platform).Preview(Scan(record), [record]);
        Assert.False(Assert.Single(plan.Items).CanRemove);
    }

    [Theory]
    [InlineData(@"USB\VID_1234&PID_5678")]
    [InlineData(@"USB\VID_1234&PID_5678\*")]
    [InlineData(@"USB\VID_1234&PID_5678\..\Properties")]
    [InlineData("/remove-device")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Enum")]
    [InlineData("USB\\VID_1234&PID_5678\\ABC\"DEF")]
    public void Broad_paths_and_command_arguments_are_rejected(string id) =>
        Assert.False(DeviceRemovalPolicy.IsInstanceId(id));

    [Fact]
    public void Wpd_display_id_resolves_to_the_exact_raw_windows_instance()
    {
        const string raw = @"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_Test#SERIAL-A&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
        const string displayed = @"SWD\WPDBUSENUM\_??_USBSTOR\Disk&Ven_Test\SERIAL-A&0";
        var record = Record(displayed);
        var platform = new FakePlatform(Node(raw) with { AuditInstanceId = displayed });
        var plan = new DeviceRemovalService(platform).Preview(Scan(record), [record]);
        var item = Assert.Single(plan.Items);
        Assert.True(item.CanRemove);
        Assert.Equal(raw, item.InstanceId);
    }

    [Fact]
    public void Canonical_device_expands_only_its_own_records_and_deduplicates_selection()
    {
        var parent = Record(canonical: "physical-one");
        var child = Record(@"USBSTOR\Disk&Ven_Test\SERIAL-A&0", "physical-one");
        var other = Record(OtherId, "physical-two");
        var platform = new FakePlatform(Node(), Node(child.DeviceInstanceId), Node(OtherId));
        var plan = new DeviceRemovalService(platform).Preview(Scan(parent, child, other), [parent, child, parent]);
        Assert.Equal(2, plan.RemovableCount);
        Assert.DoesNotContain(plan.Items, x => x.InstanceId == OtherId);
    }

    [Theory]
    [InlineData("VolumeMapping")]
    [InlineData("VolumeLabel")]
    [InlineData("USBFlags")]
    public void Shared_artifacts_cannot_be_removed_as_device_instances(string type)
    {
        var record = Record();
        record.DeviceType = type;
        var plan = new DeviceRemovalService(new FakePlatform(Node())).Preview(Scan(record), [record]);
        Assert.False(Assert.Single(plan.Items).CanRemove);
    }

    [Theory]
    [InlineData("OTHER-PC", "test")]
    [InlineData("TEST-PC", "offline-test")]
    public void Offline_or_other_machine_scan_cannot_target_current_windows(string computer, string session)
    {
        var record = Record();
        var scan = Scan(record);
        scan.ComputerName = computer;
        scan.SessionId = session;
        Assert.Throws<InvalidOperationException>(() => new DeviceRemovalService(new FakePlatform(Node())).Preview(scan, [record]));
    }

    [Fact]
    public async Task Backup_is_completed_before_mutation_and_removal_is_verified()
    {
        var record = Record();
        var platform = new FakePlatform(Node());
        var service = new DeviceRemovalService(platform);
        var result = await service.ExecuteAsync(service.Preview(Scan(record), [record]));
        Assert.Equal(1, result.RemovedCount);
        Assert.Equal(0, result.FailedCount);
        Assert.Equal(["backup", "remove:" + Id], platform.Actions);
        Assert.NotEmpty(platform.SavedResults);
    }

    [Fact]
    public async Task Failed_backup_prevents_every_removal()
    {
        var record = Record();
        var platform = new FakePlatform(Node()) { FailBackup = true };
        var service = new DeviceRemovalService(platform);
        await Assert.ThrowsAsync<IOException>(() => service.ExecuteAsync(service.Preview(Scan(record), [record])));
        Assert.Empty(platform.Removed);
    }

    [Fact]
    public async Task Reconnection_after_preview_prevents_backup_and_removal()
    {
        var record = Record();
        var platform = new FakePlatform(Node());
        var service = new DeviceRemovalService(platform);
        var plan = service.Preview(Scan(record), [record]);
        platform.Nodes[0] = Node(present: true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(plan));
        Assert.Equal(0, platform.Backups);
        Assert.Empty(platform.Removed);
    }

    [Fact]
    public async Task Reconnection_after_backup_is_detected_again()
    {
        var record = Record();
        var platform = new FakePlatform(Node());
        platform.AfterBackup = () => platform.Nodes[0] = Node(present: true);
        var service = new DeviceRemovalService(platform);
        var result = await service.ExecuteAsync(service.Preview(Scan(record), [record]));
        Assert.Equal("Blocked", Assert.Single(result.Items).Status);
        Assert.Empty(platform.Removed);
    }

    [Fact]
    public async Task New_related_component_invalidates_the_approved_plan()
    {
        const string container = "{1352bcbf-4624-43b3-9d1f-dea941d249a0}";
        var record = Record();
        var platform = new FakePlatform(Node(container: container));
        var service = new DeviceRemovalService(platform);
        var plan = service.Preview(Scan(record), [record]);
        platform.Nodes.Add(Node(OtherId, false, container));
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(plan));
        Assert.Empty(platform.Removed);
    }

    [Fact]
    public async Task Successful_exit_with_remaining_record_is_not_reported_as_removed()
    {
        var record = Record();
        var platform = new FakePlatform(Node()) { LeaveRecord = true };
        var service = new DeviceRemovalService(platform);
        var result = await service.ExecuteAsync(service.Preview(Scan(record), [record]));
        Assert.Equal(0, result.RemovedCount);
        Assert.Equal(1, result.FailedCount);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(3010)]
    public async Task Failure_or_reboot_required_does_not_claim_success(int exitCode)
    {
        var record = Record();
        var platform = new FakePlatform(Node()) { ExitCode = exitCode };
        var service = new DeviceRemovalService(platform);
        var result = await service.ExecuteAsync(service.Preview(Scan(record), [record]));
        Assert.Equal(1, result.FailedCount);
    }

    [Fact]
    public async Task Already_absent_instance_is_distinguished_from_removed()
    {
        var record = Record();
        var platform = new FakePlatform(Node());
        var service = new DeviceRemovalService(platform);
        var plan = service.Preview(Scan(record), [record]);
        platform.Nodes.Clear();
        var result = await service.ExecuteAsync(plan);
        Assert.Equal(1, result.AbsentCount);
        Assert.Empty(platform.Removed);
    }

    [Fact]
    public async Task Cancellation_after_backup_never_starts_another_command()
    {
        using var cancellation = new CancellationTokenSource();
        var record = Record();
        var platform = new FakePlatform(Node()) { AfterBackup = cancellation.Cancel };
        var service = new DeviceRemovalService(platform);
        var result = await service.ExecuteAsync(service.Preview(Scan(record), [record]), cancellationToken: cancellation.Token);
        Assert.Equal("Cancelled", Assert.Single(result.Items).Status);
        Assert.Empty(platform.Removed);
    }

    [Fact]
    public void Inventory_error_is_not_treated_as_an_empty_device_list()
    {
        var record = Record();
        var platform = new FakePlatform(Node()) { FailInventory = true };
        Assert.Throws<UnauthorizedAccessException>(() => new DeviceRemovalService(platform).Preview(Scan(record), [record]));
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(13, false)]
    public void Only_documented_configret_codes_establish_presence(uint code, bool expected) =>
        Assert.Equal(expected, WindowsDeviceRemovalPlatform.PresenceFromResult(code));

    [Fact]
    public void Unexpected_configret_is_an_error() =>
        Assert.Throws<InvalidOperationException>(() => WindowsDeviceRemovalPlatform.PresenceFromResult(5));

    private sealed class FakePlatform(params DeviceRemovalNode[] nodes) : IDeviceRemovalPlatform
    {
        public string ComputerName => "TEST-PC";
        public List<DeviceRemovalNode> Nodes { get; } = [.. nodes];
        public List<string> Removed { get; } = [];
        public List<string> Actions { get; } = [];
        public List<DeviceRemovalResult> SavedResults { get; } = [];
        public int Backups { get; private set; }
        public bool FailBackup { get; init; }
        public bool FailInventory { get; init; }
        public bool LeaveRecord { get; init; }
        public int ExitCode { get; init; }
        public Action? AfterBackup { get; set; }
        public IReadOnlyList<DeviceRemovalNode> ReadInventory() => FailInventory ? throw new UnauthorizedAccessException() : Nodes.ToArray();
        public bool IsPresent(string instanceId) => Nodes.Any(x => x.InstanceId == instanceId && x.Present == true);
        public bool InstanceExists(string instanceId) => Nodes.Any(x => x.InstanceId == instanceId);
        public void EnsureRemovalSupported() { }
        public Task<string> BackupAsync(DeviceRemovalPlan plan, CancellationToken cancellationToken)
        {
            Backups++;
            Actions.Add("backup");
            if (FailBackup)
            {
                throw new IOException("Export failed");
            }

            AfterBackup?.Invoke();
            return Task.FromResult("test-backup");
        }
        public Task<DeviceRemovalCommandResult> RemoveAsync(string instanceId)
        {
            Actions.Add("remove:" + instanceId);
            Removed.Add(instanceId);
            if (!LeaveRecord)
            {
                Nodes.RemoveAll(x => x.InstanceId == instanceId);
            }

            return Task.FromResult(new DeviceRemovalCommandResult(ExitCode, ""));
        }
        public Task SaveResultAsync(string backupDirectory, DeviceRemovalResult result)
        {
            SavedResults.Add(result);
            return Task.CompletedTask;
        }
    }
}
