using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class UsbStorageRemovalOrderTests
{
    private const string Container = "{a00051bf-b273-5687-a72c-7376856fbef1}";
    private const string Other = @"USB\VID_ABCD&PID_1234\OTHER-DEVICE";

    public static TheoryData<string, string, bool> CapturedDevices => new()
    {
        { @"USB\VID_ABCD&PID_1234\2412242109410569603146", @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0", false },
        { @"USB\VID_ABCD&PID_1234\2412281911546114543745", @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412281911546114543745&0", false },
        { @"USB\VID_11B0&PID_6298\454147455432303139303232", @"USBSTOR\Disk&Ven_Kingston&Prod_SNA-DC/U&Rev_1.08\454147455432303139303232&0", false },
        { @"USB\VID_ABCD&PID_1234\2412242109410569603146", @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0", true },
        { @"USB\VID_ABCD&PID_1234\2412281911546114543745", @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412281911546114543745&0", true },
        { @"USB\VID_11B0&PID_6298\454147455432303139303232", @"USBSTOR\Disk&Ven_Kingston&Prod_SNA-DC/U&Rev_1.08\454147455432303139303232&0", true }
    };

    [Theory]
    [MemberData(nameof(CapturedDevices))]
    public async Task Captured_usb_storage_and_wpd_nodes_are_removed_before_their_parents(string usb, string disk, bool reverse)
    {
        var world = new World(usb, disk);
        if (reverse) { world.Nodes.Reverse(); }
        var selected = new UsbDeviceRecord { DeviceInstanceId = usb };
        var scan = new AuditResult { ComputerName = world.ComputerName, SessionId = "regression" };
        scan.Devices.AddRange([selected, new() { DeviceInstanceId = disk }, new() { DeviceInstanceId = world.Wpd }]);
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(scan, [selected]);
        Assert.Equal(4, plan.RemovableCount);
        var result = await service.ExecuteAsync(plan);
        Assert.Equal(0, result.FailedCount);
        Assert.Equal(4, result.RemovedCount);
        Assert.Equal(3, DeviceRemovalDatabaseSync.CompletedRecords(plan, result).Count);
        Assert.True(world.Removed.IndexOf(disk) < world.Removed.IndexOf(usb));
        Assert.True(world.Removed.IndexOf(world.Wpd) < world.Removed.IndexOf(world.Volume));
        Assert.Equal(Other, Assert.Single(world.Nodes).InstanceId);
    }

    [Theory]
    [InlineData("connected")]
    [InlineData("hardware")]
    [InlineData("parent")]
    public async Task Real_state_changes_after_backup_still_block_disk_removal(string change)
    {
        var usb = CapturedDevices.First()[0] as string ?? throw new InvalidOperationException();
        var disk = CapturedDevices.First()[1] as string ?? throw new InvalidOperationException();
        var world = new World(usb, disk);
        world.AfterBackup = () =>
        {
            var index = world.Nodes.FindIndex(node => node.InstanceId == disk);
            var original = world.Nodes[index];
            world.Nodes[index] = change switch
            {
                "connected" => original with { Present = true },
                "hardware" => original with { HardwareIds = "changed hardware" },
                _ => original with { ParentDeviceInstanceId = Other }
            };
        };
        var selected = new UsbDeviceRecord { DeviceInstanceId = usb };
        var scan = new AuditResult { ComputerName = world.ComputerName, SessionId = "regression" };
        scan.Devices.Add(selected);
        var service = new DeviceRemovalService(world);
        var plan = service.Preview(scan, [selected]);
        var result = await service.ExecuteAsync(plan);
        Assert.Contains(result.Items, item => item.InstanceId == disk && item.Status == "Blocked");
        Assert.DoesNotContain(disk, world.Removed);
        Assert.Empty(DeviceRemovalDatabaseSync.CompletedRecords(plan, result));
    }

    private sealed class World : IDeviceRemovalPlatform
    {
        public string ComputerName => "TEST";
        public List<DeviceRemovalNode> Nodes { get; } = [];
        public List<string> Removed { get; } = [];
        public string Volume { get; }
        public string Wpd { get; }
        public Action? AfterBackup { get; set; }

        public World(string usb, string disk)
        {
            var suffix = @"\_??_" + disk.Replace('\\', '#') + "#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
            Volume = @"STORAGE\Volume" + suffix;
            Wpd = @"SWD\WPDBUSENUM" + suffix;
            Nodes.AddRange([
                new(usb, "USB", false, Container, Service: "USBSTOR"),
                new(disk, "Disk", false, Container, Service: "disk", ParentDeviceInstanceId: usb),
                new(Wpd, "WPD", false, Container, Service: "WUDFWpdFs", ParentDeviceInstanceId: Volume),
                new(Volume, "Volume", false, Container, Service: "volume"),
                new(Other, "Same model, different device", false, Service: "USBSTOR")]);
        }

        public IReadOnlyList<DeviceRemovalNode> ReadInventory() => Nodes.ToArray();
        public bool IsPresent(string id) => Nodes.Any(node => node.InstanceId == id && node.Present == true);
        public bool InstanceExists(string id) => Nodes.Any(node => node.InstanceId == id);
        public void EnsureRemovalSupported() { }
        public Task<string> BackupAsync(DeviceRemovalPlan plan, CancellationToken cancellationToken)
        {
            AfterBackup?.Invoke();
            return Task.FromResult("test-backup");
        }
        public Task<DeviceRemovalCommandResult> RemoveAsync(string id)
        {
            Removed.Add(id);
            Nodes.RemoveAll(node => node.InstanceId == id);
            // Реальное поведение из before-removal.json / after-removal.json:
            // после удаления родителя Windows больше не возвращает его ID у детей.
            for (var index = 0; index < Nodes.Count; index++)
            {
                if (Nodes[index].ParentDeviceInstanceId == id)
                {
                    Nodes[index] = Nodes[index] with { ParentDeviceInstanceId = "" };
                }
            }
            return Task.FromResult(new DeviceRemovalCommandResult(0, ""));
        }
        public Task SaveResultAsync(string directory, DeviceRemovalResult result) => Task.CompletedTask;
    }
}
