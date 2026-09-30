using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>Настоящие native registry операции и SQLite. Рабочий реестр Windows не затрагивается.</summary>
public sealed class NativeDeletionIntegrationTests
{
    [Theory]
    [InlineData("ControlSet001")]
    [InlineData("ControlSet002")]
    public void Bluetooth_cache_deletion_preserves_other_addresses_and_authentication_keys(string controlSet)
    {
        using var fixture = new Fixture();
        var root = $@"SYSTEM\{controlSet}\Services\BTHPORT\Parameters";
        var selected = root + @"\Devices\887598c2f5f2";
        var sibling = root + @"\Devices\112233445566";
        var authentication = root + @"\Keys\112233445566";
        foreach (var path in new[] { selected + @"\CachedServices", sibling, authentication })
        {
            using var key = fixture.Root.CreateSubKey(path);
            key.SetValue("keep", "sample");
        }
        var source = @"HKLM\" + selected;
        Assert.NotNull(DeviceTracePolicy.NormalizePath(source));
        var fingerprint = RegistryTraceAccess.ReadFingerprint(fixture.Root, selected, source)!;
        RegistryTraceAccess.DeleteTree(fixture.Root, selected, source, fingerprint);
        Assert.Null(fixture.Root.OpenSubKey(selected));
        using var siblingKey = fixture.Root.OpenSubKey(sibling);
        using var authenticationKey = fixture.Root.OpenSubKey(authentication);
        Assert.Equal("sample", siblingKey!.GetValue("keep"));
        Assert.Equal("sample", authenticationKey!.GetValue("keep"));
    }

    [Fact]
    public void Native_registry_preserves_slashes_inside_key_names_during_targeted_deletion()
    {
        using var fixture = new Fixture();
        const string subkey = @"USBSTOR\Disk&Ven_Kingston&Prod_SNA-DC/U&Rev_1.08\SERIAL-TEST&0";
        const string source = @"HKLM\SYSTEM\ControlSet002\Enum\" + subkey;
        using (var key = fixture.Root.CreateSubKey(subkey))
        {
            key.SetValue("FriendlyName", "Disk with slash in model");
        }
        var fingerprint = RegistryTraceAccess.ReadFingerprint(fixture.Root, subkey, source);
        Assert.NotNull(fingerprint);
        RegistryTraceAccess.DeleteTree(fixture.Root, subkey, source, fingerprint!);
        Assert.Null(fixture.Root.OpenSubKey(subkey));
        using var sibling = fixture.Root.OpenSubKey("unrelated");
        Assert.Equal("yes", sibling!.GetValue("keep"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Native_deletion_and_database_agree_even_if_protocol_storage_fails(bool failProtocol)
    {
        using var fixture = new Fixture { FailProtocol = failProtocol };
        var store = fixture.Store;
        var service = new DeviceRemovalService(fixture, store);
        var plan = service.Preview(fixture.Scan, fixture.Scan.Devices);
        Assert.Equal(2, plan.RemovableCount);
        var result = await service.ExecuteAsync(plan);
        Assert.Equal(failProtocol ? 1 : 2, result.RemovedCount);
        Assert.Equal(failProtocol ? 1 : 0, store.Load(fixture.Scan.SessionId)!.Devices.Count);
        using var sibling = fixture.Root.OpenSubKey("unrelated");
        Assert.Equal("yes", sibling!.GetValue("keep"));
        using var original = Fixture.Open(Path.Combine(result.BackupDirectory, "snapshot.hiv"));
        using var first = original.OpenSubKey("selectedA");
        using var second = original.OpenSubKey("selectedB");
        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal(failProtocol, result.ProtocolError.Length > 0);
        if (failProtocol)
        {
            Assert.Contains(result.Items, x => x.Status == "NotAttempted");
        }
    }

    [Fact]
    public async Task Changed_registry_snapshot_blocks_deletion_and_preserves_database()
    {
        using var fixture = new Fixture();
        var service = new DeviceRemovalService(fixture, fixture.Store);
        var plan = service.Preview(fixture.Scan, fixture.Scan.Devices);
        using (var changed = fixture.Root.OpenSubKey("selectedA", writable: true))
        {
            changed!.SetValue("changed", "yes");
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(plan));
        Assert.Equal(0, fixture.RemovalCalls);
        Assert.Equal(2, fixture.Store.Load(fixture.Scan.SessionId)!.Devices.Count);
    }

    [Fact]
    public async Task Failed_backup_prevents_every_native_deletion()
    {
        using var fixture = new Fixture { FailBackup = true };
        var service = new DeviceRemovalService(fixture, fixture.Store);
        var plan = service.Preview(fixture.Scan, fixture.Scan.Devices);
        await Assert.ThrowsAsync<IOException>(() => service.ExecuteAsync(plan));
        Assert.Equal(0, fixture.RemovalCalls);
        Assert.Equal(2, fixture.Store.Load(fixture.Scan.SessionId)!.Devices.Count);
    }

    [Fact]
    public async Task Cancellation_after_first_native_deletion_keeps_remaining_card()
    {
        using var cancellation = new CancellationTokenSource();
        using var fixture = new Fixture { AfterRemoval = cancellation.Cancel };
        var service = new DeviceRemovalService(fixture, fixture.Store);
        var plan = service.Preview(fixture.Scan, fixture.Scan.Devices);
        var result = await service.ExecuteAsync(plan, cancellationToken: cancellation.Token);
        Assert.Equal(1, result.RemovedCount);
        Assert.Single(fixture.Store.Load(fixture.Scan.SessionId)!.Devices);
        Assert.Contains(result.Items, x => x.Status == "Cancelled");
    }

    private sealed class Fixture : IDeviceRemovalPlatform, IRegistryTracePlatform, IDisposable
    {
        private readonly string _directory = Directory.CreateTempSubdirectory("ufa-native-integration-").FullName;
        private readonly string _file;
        public RegistryKey Root { get; private set; }
        public AuditStorage Store { get; }
        public AuditResult Scan { get; }
        public bool FailProtocol { get; init; }
        public bool FailBackup { get; init; }
        public Action? AfterRemoval { get; init; }
        public int RemovalCalls { get; private set; }
        public string ComputerName => Environment.MachineName;

        public Fixture()
        {
            _file = Path.Combine(_directory, "fixture.hiv");
            Root = Open(_file);
            foreach (var name in new[] { "selectedA", "selectedB", "unrelated" })
            {
                using var key = Root.CreateSubKey(name);
                key.SetValue("keep", "yes");
            }
            Store = new AuditStorage(Path.Combine(_directory, "database"));
            Scan = new AuditResult { ComputerName = ComputerName };
            foreach (var suffix in new[] { "A", "B" })
            {
                Scan.Devices.Add(new UsbDeviceRecord
                {
                    DeviceInstanceId = @"USB\VID_1234&PID_5678\SERIAL-" + suffix,
                    Vid = "1234",
                    Pid = "5678",
                    RawJson = JsonSerializer.Serialize(new { RegistryPath = Trace(suffix) })
                });
            }

            Store.Save(Scan);
        }

        private static string Trace(string suffix) => @"HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices\USB#VID_1234&PID_5678#SERIAL-" + suffix;
        private static string Sub(string path) => path.EndsWith("SERIAL-A", StringComparison.Ordinal) ? "selectedA"
            : path.EndsWith("SERIAL-B", StringComparison.Ordinal) ? "selectedB" : throw new InvalidOperationException("Unexpected target");
        public static RegistryKey Open(string path)
        {
            var code = RegLoadAppKey(path, out var handle, 0xF003F, 1, 0);
            if (code != 0) { handle?.Dispose(); throw new Win32Exception(code); }
            return RegistryKey.FromHandle(handle, RegistryView.Registry64);
        }
        public string? ReadTraceFingerprint(string path) => RegistryTraceAccess.ReadFingerprint(Root, Sub(path), path);
        public IReadOnlyList<DeviceRemovalNode> ReadInventory() => [];
        public bool IsPresent(string id) => false;
        public bool InstanceExists(string id) => false;
        public void EnsureRemovalSupported() { }
        public Task<string> BackupAsync(DeviceRemovalPlan plan, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (FailBackup)
            {
                throw new IOException("Controlled backup failure");
            }

            var backup = Path.Combine(_directory, "backup");
            Directory.CreateDirectory(backup);
            Root.Flush();
            Root.Dispose();
            try { File.Copy(_file, Path.Combine(backup, "snapshot.hiv")); }
            finally { Root = Open(_file); }
            return Task.FromResult(backup);
        }
        public Task<DeviceRemovalCommandResult> RemoveAsync(string id) => throw new InvalidOperationException("PnP calls forbidden in fixture");
        public Task<DeviceRemovalCommandResult> RemoveTraceAsync(DeviceRegistryTrace trace)
        {
            RegistryTraceAccess.DeleteTree(Root, Sub(trace.RegistryPath), trace.RegistryPath, trace.Fingerprint);
            RemovalCalls++;
            AfterRemoval?.Invoke();
            return Task.FromResult(new DeviceRemovalCommandResult(0, "Private hive only"));
        }
        public Task SaveResultAsync(string directory, DeviceRemovalResult result)
        {
            if (FailProtocol)
            {
                throw new IOException("Controlled protocol failure");
            }

            File.WriteAllText(Path.Combine(directory, "result.json"), JsonSerializer.Serialize(result));
            return Task.CompletedTask;
        }
        public void Dispose()
        {
            Root.Dispose();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(_directory, recursive: true);
        }
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int RegLoadAppKey(string path, out SafeRegistryHandle handle, int access, int options, int reserved);
    }
}
