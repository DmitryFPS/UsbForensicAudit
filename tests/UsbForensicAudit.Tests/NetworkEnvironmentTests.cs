using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class NetworkEnvironmentTests
{
    [Fact]
    public void Empty_snapshot_says_it_was_not_taken()
    {
        var text = new NetworkEnvironmentSnapshot().Describe();
        Assert.Contains("не снималась", text);
    }

    [Fact]
    public void Snapshot_describes_probe_honestly()
    {
        var snapshot = new NetworkEnvironmentSnapshot
        {
            TakenAtUtc = DateTimeOffset.UtcNow,
            ActiveProbeUsed = false,
            WirelessNetworks =
            [
                new WirelessNetworkRecord { Ssid = "Home", IsConnected = true, SignalPercent = 80 }
            ],
            Neighbors =
            [
                new NetworkNeighborRecord { IpAddress = "192.168.1.1", Role = NeighborRole.Gateway }
            ]
        };

        var text = snapshot.Describe();
        Assert.Contains("Сетей Wi-Fi в эфире: 1", text);
        Assert.Contains("опрос сети не проводился", text, StringComparison.OrdinalIgnoreCase);
    }
}
