using System.Text.Json;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceTraceRemovalTests
{
    private const string Id = @"USB\VID_1234&PID_5678\SERIAL-A";
    private const string Other = @"USB\VID_1234&PID_5678\SERIAL-B";
    private const string Path = @"HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices\USB#VID_1234&PID_5678#SERIAL-A";
    private static UsbDeviceRecord Record(string path = Path) => new()
    {
        DeviceInstanceId = Id,
        Vid = "1234",
        Pid = "5678",
        RawJson = JsonSerializer.Serialize(new { RegistryPath = path })
    };
    private static AuditResult Scan(UsbDeviceRecord record)
    {
        var result = new AuditResult { ComputerName = "TEST", SessionId = "test" };
        result.Devices.Add(record);
        return result;
    }

    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices\..")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_1234&PID_5678\SERIAL-A")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Control\usbflags\*")]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\app")]
    public void Broad_unrelated_and_pnp_registry_paths_are_not_directly_deleted(string path) =>
        Assert.Null(DeviceTracePolicy.NormalizePath(path));

    [Theory]
    [InlineData(Path)]
    [InlineData(@"HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\##?#USB#VID_1234&PID_5678#SERIAL-A#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt\_??_USB#VID_1234&PID_5678#SERIAL-A#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}LABEL_123")]
    public void Exact_historical_key_can_be_removed_without_remaining_pnp_instance(string path)
    {
        var record = Record(path);
        var platform = new FakeTracePlatform();
        var plan = new DeviceRemovalService(platform).Preview(Scan(record), [record]);
        var item = Assert.Single(plan.Items);
        Assert.True(item.CanRemove);
        Assert.NotNull(item.Trace);
        Assert.Equal(Id, Assert.Single(item.Trace.DeviceIds));
        Assert.Empty(platform.Actions);
    }

    [Fact]
    public void Merged_evidence_finds_only_declared_source_paths_and_deduplicates()
    {
        var record = Record();
        record.RawJson = JsonSerializer.Serialize(new
        {
            MergedRegistryEvidence = new object[]
        {
            new { RegistryPath = Path }, new { RegistryPaths = new[] { Path } }, new { Values = new { RegistryPath = Path + "BAD" } }
        }
        });
        Assert.Single(DeviceTracePolicy.SourcePaths(record));
        record.RawJson = "invalid json";
        Assert.Empty(DeviceTracePolicy.SourcePaths(record));
    }

    [Fact]
    public void Trace_of_another_serial_cannot_be_bound_to_selection()
    {
        Assert.Null(DeviceTracePolicy.Bind(Path.Replace("SERIAL-A", "SERIAL-B"), Record(), "hash"));
        var forged = new DeviceRegistryTrace(DeviceTracePolicy.NormalizePath(Path)!, "hash", [Other]);
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(forged, [], _ => false));
    }

    [Fact]
    public void Missing_owner_and_forged_model_or_root_path_cannot_authorize_a_trace()
    {
        Assert.Empty(DeviceTracePolicy.SourcePaths(new()));
        Assert.Empty(DeviceTracePolicy.SourcePaths(new() { RawJson = "[]" }));
        Assert.Null(DeviceTracePolicy.Bind(@"HKLM\SYSTEM", Record(), "hash"));
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(new(@"HKLM\SYSTEM", "hash", [Id]), [], _ => false));
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(new(Path, "hash", []), [], _ => false));
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(new(Path, "hash", [], "1234", "5678"), [], _ => false));
    }

    [Fact]
    public void Native_presence_recheck_overrides_disconnected_inventory_snapshot()
    {
        var trace = DeviceTracePolicy.Bind(Path, Record(), "hash")!;
        var node = new DeviceRemovalNode(Id, "USB", false, Service: "USBSTOR");
        Assert.Contains("подключены", DeviceTracePolicy.ProtectionReason(trace, [node], _ => true));
        Assert.Contains("подключено", DeviceTracePolicy.ProtectionReason(trace, [], _ => true));
    }

    [Fact]
    public async Task Registry_delete_exception_is_reported_and_does_not_claim_success()
    {
        var record = Record();
        var platform = new FakeTracePlatform { FailDelete = true };
        var service = new DeviceRemovalService(platform);
        var result = await service.ExecuteAsync(service.Preview(Scan(record), [record]));
        Assert.Equal("Failed", Assert.Single(result.Items).Status);
        Assert.Equal(0, result.RemovedCount);
        Assert.Equal("original", platform.Fingerprint);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(null)]
    public void Connected_or_unknown_owner_protects_history(bool? present)
    {
        var record = Record();
        var platform = new FakeTracePlatform();
        platform.Nodes.Add(new(Id, "USB", present, Service: "USBSTOR"));
        var plan = new DeviceRemovalService(platform).Preview(Scan(record), [record]);
        Assert.All(plan.Items, item => Assert.False(item.CanRemove));
    }

    [Fact]
    public void Usbflags_is_model_wide_and_protected_while_any_same_model_instance_is_present()
    {
        var record = Record(@"HKLM\SYSTEM\ControlSet001\Control\usbflags\123456780100");
        record.DeviceType = "USBFlags";
        var platform = new FakeTracePlatform();
        var service = new DeviceRemovalService(platform);
        Assert.True(Assert.Single(service.Preview(Scan(record), [record]).Items).CanRemove);
        platform.Nodes.Add(new(Other, "other", true, Service: "USBSTOR"));
        Assert.False(Assert.Single(service.Preview(Scan(record), [record]).Items).CanRemove);
        record.Pid = "9999";
        Assert.False(Assert.Single(service.Preview(Scan(record), [record]).Items).CanRemove);
    }

    [Fact]
    public async Task Registry_trace_uses_backup_then_exact_delete_and_verifies_absence()
    {
        var record = Record();
        var platform = new FakeTracePlatform();
        var service = new DeviceRemovalService(platform);
        var result = await service.ExecuteAsync(service.Preview(Scan(record), [record]));
        Assert.Equal(1, result.RemovedCount);
        Assert.Equal(["backup", "delete:" + DeviceTracePolicy.NormalizePath(Path)], platform.Actions);
    }

    [Fact]
    public async Task Registry_change_after_backup_blocks_deletion()
    {
        var record = Record();
        var platform = new FakeTracePlatform();
        platform.AfterBackup = () => platform.Fingerprint = "modified";
        var service = new DeviceRemovalService(platform);
        var result = await service.ExecuteAsync(service.Preview(Scan(record), [record]));
        Assert.Equal("Blocked", Assert.Single(result.Items).Status);
        Assert.Equal(["backup"], platform.Actions);
    }

    [Fact]
    public async Task Reconnection_after_backup_blocks_history_deletion()
    {
        var record = Record();
        var platform = new FakeTracePlatform();
        platform.AfterBackup = () => platform.Nodes.Add(new(Id, "USB", true, Service: "USBSTOR"));
        var service = new DeviceRemovalService(platform);
        var result = await service.ExecuteAsync(service.Preview(Scan(record), [record]));
        Assert.Equal("Blocked", Assert.Single(result.Items).Status);
        Assert.Equal(["backup"], platform.Actions);
    }

    [Fact]
    public void Inaccessible_trace_is_explained_without_hiding_available_pnp_instance()
    {
        var record = Record();
        var platform = new FakeTracePlatform { DenyTrace = true };
        platform.Nodes.Add(new(Id, "USB", false, Service: "USBSTOR"));
        var plan = new DeviceRemovalService(platform).Preview(Scan(record), [record]);
        Assert.Equal(1, plan.RemovableCount);
        Assert.Contains(plan.Items, x => !x.CanRemove && x.Reason.Contains("прочитать"));
    }

    private sealed class FakeTracePlatform : IDeviceRemovalPlatform, IRegistryTracePlatform
    {
        public string ComputerName => "TEST";
        public List<DeviceRemovalNode> Nodes { get; } = [];
        public List<string> Actions { get; } = [];
        public string? Fingerprint { get; set; } = "original";
        public Action? AfterBackup { get; set; }
        public bool DenyTrace { get; init; }
        public bool FailDelete { get; init; }
        public string? ReadTraceFingerprint(string path) => DenyTrace ? throw new UnauthorizedAccessException() : Fingerprint;
        public Task<DeviceRemovalCommandResult> RemoveTraceAsync(DeviceRegistryTrace trace)
        {
            Actions.Add("delete:" + trace.RegistryPath);
            if (FailDelete)
            {
                throw new UnauthorizedAccessException("Delete denied");
            }

            Fingerprint = null;
            return Task.FromResult(new DeviceRemovalCommandResult(0, ""));
        }
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
        public Task<DeviceRemovalCommandResult> RemoveAsync(string id) => throw new InvalidOperationException("PnP must not be called for history");
        public Task SaveResultAsync(string directory, DeviceRemovalResult result) => Task.CompletedTask;
    }
}
