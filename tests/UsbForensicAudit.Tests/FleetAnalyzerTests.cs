using System;
using System.Linq;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Флот: устройство с одним серийником, появившееся на нескольких машинах,
/// помечается как перемещавшееся; ключ идентичности — серийник, иначе VID:PID;
/// устройства без опознавательных признаков в анализ не берутся.
/// </summary>
public sealed class FleetAnalyzerTests
{
    private static AuditResult Machine(string name, params UsbDeviceRecord[] devices)
    {
        var result = new AuditResult { ComputerName = name };
        result.Devices.AddRange(devices);
        return result;
    }

    private static UsbDeviceRecord Flash(string serial) => new()
    {
        Vid = "0951",
        Pid = "1666",
        Serial = serial,
        DeviceKind = DeviceKindResolver.Storage
    };

    [Fact]
    public void Same_serial_on_two_machines_is_cross_machine()
    {
        var summary = FleetAnalyzer.Analyze(
        [
            Machine("PC-1", Flash("SN-COMMON")),
            Machine("PC-2", Flash("SN-COMMON")),
            Machine("PC-3", Flash("SN-OTHER"))
        ]);

        Assert.Equal(3, summary.MachineCount);
        Assert.True(summary.HasCrossMachineDevices);
        var moved = Assert.Single(summary.CrossMachineDevices);
        Assert.Equal("SN:SN-COMMON", moved.IdentityKey);
        Assert.Equal(2, moved.MachineCount);
        Assert.Contains("PC-1", moved.Machines);
        Assert.Contains("PC-2", moved.Machines);
    }

    [Fact]
    public void Device_on_single_machine_is_not_cross_machine()
    {
        var summary = FleetAnalyzer.Analyze([Machine("PC-1", Flash("SN-1"))]);

        Assert.False(summary.HasCrossMachineDevices);
        Assert.Contains("не обнаружено", summary.Verdict());
    }

    [Fact]
    public void Falls_back_to_vidpid_when_no_serial()
    {
        var noSerial = new UsbDeviceRecord { Vid = "AAAA", Pid = "BBBB", DeviceKind = DeviceKindResolver.Storage };
        var summary = FleetAnalyzer.Analyze(
        [
            Machine("PC-1", noSerial),
            Machine("PC-2", new UsbDeviceRecord { Vid = "AAAA", Pid = "BBBB" })
        ]);

        var moved = Assert.Single(summary.CrossMachineDevices);
        Assert.Equal("VIDPID:AAAA:BBBB", moved.IdentityKey);
    }

    [Fact]
    public void Device_without_identity_is_ignored()
    {
        var anonymous = new UsbDeviceRecord { Vid = "", Pid = "", Serial = "" };
        var summary = FleetAnalyzer.Analyze([Machine("PC-1", anonymous), Machine("PC-2", anonymous)]);

        Assert.Empty(summary.Devices);
    }

    [Fact]
    public void Verdict_counts_machines_and_movers()
    {
        var summary = FleetAnalyzer.Analyze(
        [
            Machine("PC-1", Flash("SN-X")),
            Machine("PC-2", Flash("SN-X"))
        ]);

        Assert.Contains("Обработано машин: 2", summary.Verdict());
        Assert.Contains("на нескольких машинах: 1", summary.Verdict());
    }
}
