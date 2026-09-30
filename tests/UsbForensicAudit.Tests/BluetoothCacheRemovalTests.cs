using System.IO;
using System.Text.Json;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class BluetoothCacheRemovalTests : IDisposable
{
    private const string Cache = @"HKLM\SYSTEM\ControlSet001\Services\BTHPORT\Parameters\Devices\887598c2f5f2";
    private const string Phone = @"BTHENUM\Dev_887598C2F5F2\7&2768a9f8&0&BluetoothDevice_887598C2F5F2";
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "Bluetooth-cache-test-" + Guid.NewGuid().ToString("N"));

    private static UsbDeviceRecord CacheRecord() => new()
    {
        DeviceInstanceId = Cache,
        DeviceType = "BluetoothCache",
        FriendlyName = "Galaxy S9+",
        RawJson = JsonSerializer.Serialize(new { RegistryPath = Cache })
    };

    private static AuditResult Scan(bool withPhone = true)
    {
        var scan = new AuditResult { ComputerName = "TEST", SessionId = "cache-test" };
        scan.Devices.Add(CacheRecord());
        if (withPhone) { scan.Devices.Add(new() { DeviceInstanceId = Phone, Service = "BthEnum" }); }
        DeviceTransportClassifier.ClassifyAll(scan.Devices);
        DeviceIdentityGraph.Process(scan.Devices);
        return scan;
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Selecting_cache_includes_live_inventory_identity_and_deletes_cache_last(bool withPhoneCard)
    {
        var scan = Scan(withPhoneCard);
        var world = new World();
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(scan, [scan.Devices[0]]);
        Assert.Equal(2, plan.RemovableCount);
        var result = await service.ExecuteAsync(plan);
        Assert.Equal(2, result.RemovedCount);
        Assert.Equal(0, result.FailedCount);
        Assert.Equal(["backup", Phone, DeviceTracePolicy.NormalizePath(Cache)!], world.Actions);
        Assert.Equal(scan.Devices.Count, DeviceRemovalDatabaseSync.CompletedRecords(plan, result).Count);
        Assert.Contains(scan.Devices[0], DeviceListPresentation.Select(scan.Devices, false, "Galaxy"));
        if (withPhoneCard) { Assert.Equal(scan.Devices[0].CanonicalDeviceId, scan.Devices[1].CanonicalDeviceId); }
        Assert.Equal("Историческая запись Bluetooth", scan.Devices[0].CategoryText);
        Assert.Contains("ControlSet001", scan.Devices[0].InstanceSummary);
        Assert.Equal("По записи кэша неизвестно", scan.Devices[0].LastDisconnectedText);
    }

    [Fact]
    public async Task Orphan_cache_is_removable_after_all_pnp_nodes_have_gone()
    {
        var world = new World();
        world.Nodes.Clear();
        var scan = Scan(false);
        var service = new DeviceRemovalService(world);
        var result = await service.ExecuteAsync(service.Preview(scan, scan.Devices));
        Assert.Equal(1, result.RemovedCount);
        Assert.Null(world.Fingerprint);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(null)]
    public void Connected_or_unknown_bluetooth_prevents_cache_deletion(bool? present)
    {
        var world = new World();
        world.Nodes[0] = world.Nodes[0] with { Present = present };
        var scan = Scan();
        var plan = new DeviceRemovalService(world).Preview(scan, [scan.Devices[0]]);
        Assert.Equal(0, plan.RemovableCount);
    }

    [Theory]
    [InlineData("pnp failure")]
    [InlineData("reconnected")]
    [InlineData("cache changed")]
    public async Task Incomplete_unpair_or_changed_state_keeps_cache_and_database(string scenario)
    {
        var world = new World { Scenario = scenario };
        var scan = Scan();
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(scan, scan.Devices);
        var result = await service.ExecuteAsync(plan);
        Assert.True(result.FailedCount > 0);
        Assert.NotNull(world.Fingerprint);
        Assert.Empty(DeviceRemovalDatabaseSync.CompletedRecords(plan, result));
    }

    [Theory]
    [InlineData(@"HKLM\SYSTEM\ControlSet001\Services\BTHPORT\Parameters\Devices")]
    [InlineData(@"HKLM\SYSTEM\ControlSet001\Services\BTHPORT\Parameters\Keys\887598c2f5f2")]
    [InlineData(Cache + @"\..")]
    [InlineData(Cache + "0")]
    [InlineData(@"HKLM\SYSTEM\ControlSet001\Services\BTHPORT\Parameters\Devices\000000000000")]
    public void Cache_policy_rejects_parent_keys_authentication_keys_and_invalid_addresses(string path)
    {
        Assert.Empty(BluetoothCacheIdentity.AddressFromPath(path));
        Assert.Null(DeviceTracePolicy.NormalizePath(path));
    }

    [Fact]
    public void Same_name_or_different_address_cannot_authorize_deletion()
    {
        var record = CacheRecord();
        record.DeviceInstanceId = Cache.Replace("887598c2f5f2", "112233445566");
        Assert.Null(DeviceTracePolicy.Bind(Cache, record, "hash"));
    }

    [Fact]
    public void Database_cleanup_backs_up_matching_network_cache_and_preserves_other_sources_and_sessions()
    {
        var scan = Scan(false);
        var currentPath = Cache.Replace("ControlSet001", "CurrentControlSet");
        scan.NetworkConnections.Add(new() { Kind = NetworkConnectionKind.Bluetooth, Name = "Galaxy", Provenance = currentPath });
        scan.NetworkConnections.Add(new() { Kind = NetworkConnectionKind.Bluetooth, Name = "Other", Provenance = currentPath.Replace("887598c2f5f2", "112233445566") });
        scan.NetworkConnections.Add(new() { Kind = NetworkConnectionKind.Bluetooth, Name = "Historical event", Provenance = "Windows EventLog" });
        var storage = new AuditStorage(_directory);
        storage.Save(scan);
        var other = Scan(false);
        other.SessionId = "other-session";
        other.NetworkConnections.AddRange(scan.NetworkConnections);
        storage.Save(other);
        var journal = File.ReadAllBytes(storage.JsonlPath);
        var result = storage.DeleteDeviceRecords(scan.SessionId, [Cache]);
        Assert.Equal(1, result.RemovedCount);
        Assert.Equal(1, result.NetworkRemovedCount);
        var loaded = storage.Load(scan.SessionId)!;
        Assert.Empty(loaded.Devices);
        Assert.Equal(["Other", "Historical event"], loaded.NetworkConnections.Select(x => x.Name));
        Assert.Equal(3, storage.Load("other-session")!.NetworkConnections.Count);
        using var backup = JsonDocument.Parse(File.ReadAllText(Path.Combine(result.BackupDirectory, "devices.json")));
        Assert.Equal("Galaxy", backup.RootElement.GetProperty("NetworkRecords")[0].GetProperty("Name").GetString());
        Assert.Equal(journal, File.ReadAllBytes(storage.JsonlPath));
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory)) { Directory.Delete(_directory, true); }
    }

    private sealed class World : IDeviceRemovalPlatform, IRegistryTracePlatform
    {
        public string ComputerName => "TEST";
        public List<DeviceRemovalNode> Nodes { get; } = [new(Phone, "Phone", false, Service: "BthEnum")];
        public string? Fingerprint { get; set; } = "original";
        public string Scenario { get; init; } = "";
        public List<string> Actions { get; } = [];
        public IReadOnlyList<DeviceRemovalNode> ReadInventory() => Nodes.ToArray();
        public bool IsPresent(string id) => Nodes.Any(node => node.InstanceId == id && node.Present == true);
        public bool InstanceExists(string id) => Nodes.Any(node => node.InstanceId == id);
        public void EnsureRemovalSupported() { }
        public string? ReadTraceFingerprint(string path) => Fingerprint;
        public Task<string> BackupAsync(DeviceRemovalPlan plan, CancellationToken cancellationToken)
        {
            Actions.Add("backup");
            if (Scenario == "reconnected") { Nodes[0] = Nodes[0] with { Present = true }; }
            return Task.FromResult("backup");
        }
        public Task<DeviceRemovalCommandResult> RemoveAsync(string id)
        {
            Actions.Add(id);
            if (Scenario == "pnp failure") { return Task.FromResult(new DeviceRemovalCommandResult(5, "denied")); }
            Nodes.RemoveAll(node => node.InstanceId == id);
            if (Scenario == "cache changed") { Fingerprint = "changed"; }
            return Task.FromResult(new DeviceRemovalCommandResult(0, ""));
        }
        public Task<DeviceRemovalCommandResult> RemoveTraceAsync(DeviceRegistryTrace trace)
        {
            Assert.Empty(Nodes);
            Actions.Add(trace.RegistryPath);
            Fingerprint = null;
            return Task.FromResult(new DeviceRemovalCommandResult(0, ""));
        }
        public Task SaveResultAsync(string directory, DeviceRemovalResult result) => Task.CompletedTask;
    }
}
