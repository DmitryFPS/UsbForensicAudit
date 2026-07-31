using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceCountSummaryTests
{
    private static UsbDeviceRecord Record(string canonical, string kind = DeviceKindResolver.Storage) => new()
    {
        CanonicalDeviceId = canonical,
        DeviceInstanceId = canonical,
        DeviceKind = kind
    };

    [Fact]
    public void One_flash_drive_seen_in_three_registry_branches_is_counted_once()
    {
        var summary = DeviceCountSummary.FromDevices(
        [
            Record("udisk-2412"),
            Record("udisk-2412"),
            Record("udisk-2412", DeviceKindResolver.PortableDevice)
        ]);

        Assert.Equal(1, summary.PhysicalDevices);
        Assert.Equal(3, summary.RegistryRecords);
        Assert.Equal(2, summary.MergedRecords);
    }

    [Fact]
    public void Hubs_and_registry_traces_are_kept_out_of_the_headline_number()
    {
        var summary = DeviceCountSummary.FromDevices(
        [
            Record("udisk-2412"),
            Record("hub-1", DeviceKindResolver.Infrastructure),
            Record("usbflags-2717FF40", DeviceKindResolver.RegistryTrace)
        ]);

        Assert.Equal(1, summary.PhysicalDevices);
        Assert.Equal(1, summary.InfrastructureRecords);
        Assert.Equal(1, summary.RegistryTraceRecords);
    }

    [Fact]
    public void Records_without_a_canonical_id_fall_back_to_their_instance_id()
    {
        var summary = DeviceCountSummary.FromDevices(
        [
            new UsbDeviceRecord { DeviceInstanceId = @"USBSTOR\Disk&Ven_A\1", DeviceKind = DeviceKindResolver.Storage },
            new UsbDeviceRecord { DeviceInstanceId = @"USBSTOR\Disk&Ven_B\2", DeviceKind = DeviceKindResolver.Storage }
        ]);

        Assert.Equal(2, summary.PhysicalDevices);
        Assert.Equal(0, summary.MergedRecords);
    }

    [Fact]
    public void Description_states_the_headline_number_and_explains_the_rest()
    {
        var text = DeviceCountSummary.FromDevices(
        [
            Record("udisk-2412"),
            Record("udisk-2412"),
            Record("hub-1", DeviceKindResolver.Infrastructure)
        ]).Describe();

        Assert.Contains("Физических устройств: 1", text, StringComparison.Ordinal);
        Assert.Contains("сведены", text, StringComparison.Ordinal);
        Assert.Contains("шине", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Empty_scan_says_so_plainly()
    {
        Assert.Equal("Устройств не обнаружено.", DeviceCountSummary.Empty.Describe());
        Assert.Equal("Устройств не обнаружено.", DeviceCountSummary.FromDevices([]).Describe());
    }

    [Fact]
    public void Only_infrastructure_found_does_not_claim_physical_devices()
    {
        var summary = DeviceCountSummary.FromDevices([Record("hub-1", DeviceKindResolver.Infrastructure)]);

        Assert.Equal(0, summary.PhysicalDevices);
        Assert.Contains("выделить не удалось", summary.Describe(), StringComparison.Ordinal);
    }
}
