using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class BluetoothDeviceRemovalTests
{
    private const string Address = "887598C2F5F2";
    private const string Phone = @"BTHENUM\Dev_887598C2F5F2\7&2768a9f8&0&BluetoothDevice_887598C2F5F2";
    private const string Service = @"BTHENUM\{0000112f-0000-1000-8000-00805f9b34fb}_VID&00010075_PID&0100\7&2768a9f8&0&887598C2F5F2_C00000000";
    private const string LePhone = @"BTHLE\Dev_887598c2f5f2\7&2832959&0&887598c2f5f2";
    private const string LeService = @"BTHLEDEVICE\{00001800-0000-1000-8000-00805f9b34fb}_887598c2f5f2\8&26e4c222&0&0014";
    private const string Audio = @"BTHHFENUM\BthHFPAudio\8&2b845b03&0&97";
    private const string ClassicContainer = "{82e332c1-0e1a-5123-843d-132f3a51b2f8}";
    private const string LeContainer = "{13bb1b83-5b34-591d-a3d0-a4adb9358d15}";
    private static DeviceRemovalNode Node(string id, string container = ClassicContainer, bool? present = false) =>
        new(id, "Galaxy S9+ пользователя Дмитрий", present, container, "", "{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}");

    [Fact]
    public void Selecting_a_phone_profile_includes_its_classic_le_and_audio_components_only()
    {
        var family = new[] { Node(Phone), Node(Service), Node(LePhone, LeContainer), Node(LeService, LeContainer), Node(Audio) };
        var another = Node(Phone.Replace(Address, "112233445566"), "{622f1c71-a006-4427-9220-8995cfe9657b}");
        var radio = Node(@"USB\VID_8087&PID_0033\RADIO", "{a3a90a89-97b8-4c37-b83e-c39fce6259b8}") with { Service = "BTHUSB" };
        var platform = new FakePlatform([.. family, another, radio]);
        var scan = new AuditResult { ComputerName = "TEST", SessionId = "current" };
        scan.Devices.AddRange(platform.Nodes.Select(x => new UsbDeviceRecord { DeviceInstanceId = x.InstanceId, FriendlyName = x.Name }));
        var selected = scan.Devices.Single(x => x.DeviceInstanceId == Service);
        var plan = new DeviceRemovalService(platform).Preview(scan, [selected]);
        Assert.Equal(family.Length, plan.RemovableCount);
        Assert.Equal(0, plan.ProtectedCount);
        Assert.Equal(family.Length, plan.DatabaseRecords.Count);
        Assert.DoesNotContain(plan.Items, x => x.InstanceId == another.InstanceId || x.InstanceId == radio.InstanceId);
        Assert.All(family, x => Assert.Contains(plan.Items, item => item.InstanceId == x.InstanceId));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(null)]
    public void Connected_or_unverifiable_le_component_blocks_the_whole_phone(bool? present)
    {
        var root = Node(Phone);
        var family = DeviceRemovalPolicy.Related(root, [root, Node(LeService, LeContainer, present)]);
        Assert.Equal(2, family.Count);
        Assert.NotEmpty(DeviceRemovalPolicy.ProtectionReason(root, family));
    }

    [Fact]
    public void A_container_with_conflicting_remote_addresses_is_never_a_removal_identity()
    {
        var root = Node(Phone);
        var other = Node(Phone.Replace(Address, "112233445566"));
        var family = DeviceRemovalPolicy.Related(root, [root, other]);
        Assert.Contains("разные адреса", DeviceRemovalPolicy.ProtectionReason(root, family));
    }

    [Theory]
    [InlineData(@"BTH\MS_BTHBRB\7&LOCAL&0&1", "BthEnum")]
    [InlineData(@"USB\VID_8087&PID_0033\RADIO", "BTHUSB")]
    [InlineData(@"USB\VID_8087&PID_0033\RADIO", "BTHMINI")]
    [InlineData(Audio, "BthHFAud")]
    public void Radio_local_enumerator_and_unattributed_audio_are_protected(string id, string service)
    {
        var node = Node(id) with { Service = service };
        Assert.NotEmpty(DeviceRemovalPolicy.ProtectionReason(node, [node]));
    }

    [Theory]
    [InlineData(Phone)]
    [InlineData(Service)]
    [InlineData(LePhone)]
    [InlineData(LeService)]
    public void Supported_bluetooth_ids_require_a_specific_remote_address(string id)
    {
        Assert.Equal(Address, BluetoothEnumeratorId.DeviceAddress(id));
        Assert.True(DeviceRemovalPolicy.IsInstanceId(id));
    }

    [Theory]
    [InlineData(@"BTHENUM\LOCALMFG&0002\7&LOCAL&0&887598C2F5F2_C00000000")]
    [InlineData(@"BTHENUM\Dev_887598C2F5F2\7&0&BluetoothDevice_112233445566")]
    [InlineData(@"BTHENUM\Dev_000000000000\7&0&000000000000")]
    [InlineData(@"BTHENUM\Dev_FFFFFFFFFFFF\7&0&FFFFFFFFFFFF")]
    [InlineData(@"BTHLEDEVICE\{------------------------------------}_887598c2f5f2\8&0&1")]
    [InlineData(@"BTHENUM\Dev_887598C2F5F2\*")]
    [InlineData(@"BTHENUM\Dev_887598C2F5F2\..")]
    public void Malformed_ambiguous_and_broad_bluetooth_ids_are_rejected(string id) =>
        Assert.False(DeviceRemovalPolicy.IsInstanceId(id));

    [Theory]
    [InlineData(0u)]
    [InlineData(1168u)]
    public async Task Native_adapter_unpairs_exact_classic_address_then_removes_remaining_pnp_id(uint unpairResult)
    {
        var actions = new List<string>();
        var platform = new WindowsDeviceRemovalPlatform("unused", _ => false, _ => true,
            (exe, args, _) =>
            {
                Assert.Equal("pnputil.exe", exe);
                Assert.Equal(["/remove-device", Phone], args);
                actions.Add("pnp");
                return Task.FromResult(new DeviceRemovalCommandResult(0, "done"));
            }, () => actions.Add("permission"), removeBluetooth: address =>
            {
                Assert.Equal(Convert.ToUInt64(Address, 16), address);
                actions.Add("unpair");
                return unpairResult;
            });
        Assert.Equal(0, (await platform.RemoveAsync(Phone)).ExitCode);
        Assert.Equal(["permission", "unpair", "pnp"], actions);
    }

    [Fact]
    public async Task Failed_unpair_does_not_report_success_or_start_pnp_removal()
    {
        var platform = new WindowsDeviceRemovalPlatform("unused", _ => false, _ => true,
            (_, _, _) => throw new Exception("PnP must not start after failed unpair"), () => { }, removeBluetooth: _ => 5);
        Assert.Equal(5, (await platform.RemoveAsync(Phone)).ExitCode);
    }

    [Fact]
    public async Task Unpair_that_already_removed_the_pnp_record_needs_no_second_command()
    {
        var platform = new WindowsDeviceRemovalPlatform("unused", _ => false, _ => false,
            (_, _, _) => throw new Exception("PnP record already absent"), () => { }, removeBluetooth: _ => 0);
        Assert.Equal(0, (await platform.RemoveAsync(Phone)).ExitCode);
    }

    [Fact]
    public async Task Reconnected_phone_is_not_unpaired()
    {
        var platform = new WindowsDeviceRemovalPlatform("unused", _ => true, _ => true,
            (_, _, _) => throw new Exception("Connected device"), () => { },
            removeBluetooth: _ => throw new Exception("Connected device must not be unpaired"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => platform.RemoveAsync(Phone));
    }

    [Fact]
    public async Task Reconnection_during_unpair_blocks_further_pnp_removal()
    {
        var present = false;
        var platform = new WindowsDeviceRemovalPlatform("unused", _ => present, _ => true,
            (_, _, _) => throw new Exception("Reconnected device"), () => { },
            removeBluetooth: _ => { present = true; return 0; });
        await Assert.ThrowsAsync<InvalidOperationException>(() => platform.RemoveAsync(Phone));
    }

    [Theory]
    [InlineData(Service)]
    [InlineData(LePhone)]
    [InlineData(LeService)]
    [InlineData(Audio)]
    public async Task Profiles_and_le_nodes_use_exact_pnp_id_without_classic_unpair_api(string id)
    {
        var platform = new WindowsDeviceRemovalPlatform("unused", _ => false, _ => true,
            (exe, args, _) =>
            {
                Assert.Equal("pnputil.exe", exe);
                Assert.Equal(["/remove-device", id], args);
                return Task.FromResult(new DeviceRemovalCommandResult(0, "done"));
            }, () => { }, removeBluetooth: _ => throw new Exception("Not a classic pairing target"));
        Assert.Equal(0, (await platform.RemoveAsync(id)).ExitCode);
    }

    [Fact]
    public void Driverless_remote_profile_is_identified_by_its_valid_uuid_and_address()
    {
        var node = Node(Service) with { ClassGuid = "", Service = "" };
        Assert.Empty(DeviceRemovalPolicy.ProtectionReason(node, [node]));
    }

    private sealed class FakePlatform(params DeviceRemovalNode[] nodes) : IDeviceRemovalPlatform
    {
        public string ComputerName => "TEST";
        public IReadOnlyList<DeviceRemovalNode> Nodes { get; } = nodes;
        public IReadOnlyList<DeviceRemovalNode> ReadInventory() => Nodes;
        public bool IsPresent(string instanceId) => Nodes.Any(x => x.InstanceId == instanceId && x.Present == true);
        public bool InstanceExists(string instanceId) => Nodes.Any(x => x.InstanceId == instanceId);
        public void EnsureRemovalSupported() { }
        public Task<string> BackupAsync(DeviceRemovalPlan plan, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DeviceRemovalCommandResult> RemoveAsync(string instanceId) => throw new NotSupportedException();
        public Task SaveResultAsync(string backupDirectory, DeviceRemovalResult result) => throw new NotSupportedException();
    }
}
