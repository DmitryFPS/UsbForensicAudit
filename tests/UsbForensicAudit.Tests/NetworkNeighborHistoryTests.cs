using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class NetworkNeighborHistoryTests
{
    private static readonly DateTimeOffset FirstCapture = new(2026, 7, 1, 10, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset SecondCapture = new(2026, 7, 1, 11, 0, 0, TimeSpan.Zero);

    [Fact]
    public void First_observation_creates_history_entry()
    {
        var neighbor = new NetworkNeighborRecord
        {
            IpAddress = "192.168.1.50",
            MacAddress = "00-1A-2B-3C-4D-5E",
            HostName = "laptop.local",
            Network = "192.168.1.0/24"
        };

        var history = NetworkNeighborHistoryAccumulator.Merge([], [neighbor], FirstCapture);

        var entry = Assert.Single(history);
        Assert.Equal(1, entry.TimesSeen);
        Assert.Equal(FirstCapture, entry.FirstSeenUtc);
        Assert.Equal(FirstCapture, entry.LastSeenUtc);
        Assert.False(entry.IsRandomizedMac);
        Assert.False(entry.IdentifiedByIpOnly);
        Assert.Contains("192.168.1.50", entry.IpAddresses);
        Assert.Contains("laptop.local", entry.Names);
        Assert.Single(entry.Observations);
    }

    [Fact]
    public void Same_factory_mac_merges_into_one_entry()
    {
        var first = new NetworkNeighborRecord
        {
            IpAddress = "192.168.1.50",
            MacAddress = "00-1A-2B-3C-4D-5E",
            HostName = "laptop.local"
        };
        var second = new NetworkNeighborRecord
        {
            IpAddress = "192.168.1.77",
            MacAddress = "00:1a:2b:3c:4d:5e",
            NetbiosName = "LAPTOP"
        };

        var history = NetworkNeighborHistoryAccumulator.Merge([], [first], FirstCapture);
        history = NetworkNeighborHistoryAccumulator.Merge(history, [second], SecondCapture);

        var entry = Assert.Single(history);
        Assert.Equal(2, entry.TimesSeen);
        Assert.Equal(FirstCapture, entry.FirstSeenUtc);
        Assert.Equal(SecondCapture, entry.LastSeenUtc);
        Assert.Contains("192.168.1.50", entry.IpAddresses);
        Assert.Contains("192.168.1.77", entry.IpAddresses);
        Assert.Contains("laptop.local", entry.Names);
        Assert.Contains("LAPTOP", entry.Names);
        Assert.Equal(2, entry.Observations.Count);
    }

    [Fact]
    public void Randomized_mac_is_flagged_and_never_merged()
    {
        // Второй бит первого октета установлен: адрес назначен на месте.
        var first = new NetworkNeighborRecord { IpAddress = "192.168.1.60", MacAddress = "0A-11-22-33-44-55" };
        var second = new NetworkNeighborRecord { IpAddress = "192.168.1.60", MacAddress = "0A-11-22-33-44-55" };

        var history = NetworkNeighborHistoryAccumulator.Merge([], [first], FirstCapture);
        history = NetworkNeighborHistoryAccumulator.Merge(history, [second], SecondCapture);

        Assert.Equal(2, history.Count);
        Assert.All(history, x => Assert.True(x.IsRandomizedMac));
        Assert.All(history, x => Assert.Equal(1, x.TimesSeen));
        Assert.All(history, x => Assert.Contains("Ненадёжно", x.IdentityText));
    }

    [Fact]
    public void Neighbor_without_mac_merges_by_ip()
    {
        var first = new NetworkNeighborRecord { IpAddress = "192.168.1.90" };
        var second = new NetworkNeighborRecord { IpAddress = "192.168.1.90", HostName = "printer" };

        var history = NetworkNeighborHistoryAccumulator.Merge([], [first], FirstCapture);
        history = NetworkNeighborHistoryAccumulator.Merge(history, [second], SecondCapture);

        var entry = Assert.Single(history);
        Assert.Equal(2, entry.TimesSeen);
        Assert.True(entry.IdentifiedByIpOnly);
        Assert.Contains("printer", entry.Names);
        Assert.Contains("только по IP", entry.IdentityText);
    }

    [Fact]
    public void Merge_keeps_unique_names_and_networks_without_duplicates()
    {
        var neighbor = new NetworkNeighborRecord
        {
            IpAddress = "192.168.1.50",
            MacAddress = "00-1A-2B-3C-4D-5E",
            HostName = "laptop.local",
            Network = "192.168.1.0/24"
        };

        var history = NetworkNeighborHistoryAccumulator.Merge([], [neighbor], FirstCapture);
        history = NetworkNeighborHistoryAccumulator.Merge(history, [neighbor], SecondCapture);

        var entry = Assert.Single(history);
        Assert.Single(entry.IpAddresses);
        Assert.Single(entry.Names);
        Assert.Single(entry.Networks);
    }

    [Fact]
    public void Merge_does_not_mutate_existing_history()
    {
        var neighbor = new NetworkNeighborRecord { IpAddress = "192.168.1.50", MacAddress = "00-1A-2B-3C-4D-5E" };
        var original = NetworkNeighborHistoryAccumulator.Merge([], [neighbor], FirstCapture);

        NetworkNeighborHistoryAccumulator.Merge(original, [neighbor], SecondCapture);

        var entry = Assert.Single(original);
        Assert.Equal(1, entry.TimesSeen);
        Assert.Equal(FirstCapture, entry.LastSeenUtc);
    }

    [Fact]
    public void Role_upgrades_when_device_turns_out_more_important()
    {
        var asNeighbor = new NetworkNeighborRecord
        {
            IpAddress = "192.168.1.1",
            MacAddress = "00-1A-2B-3C-4D-5E",
            Role = NeighborRole.Neighbor
        };
        var asGateway = new NetworkNeighborRecord
        {
            IpAddress = "192.168.1.1",
            MacAddress = "00-1A-2B-3C-4D-5E",
            Role = NeighborRole.Gateway
        };

        var history = NetworkNeighborHistoryAccumulator.Merge([], [asNeighbor], FirstCapture);
        history = NetworkNeighborHistoryAccumulator.Merge(history, [asGateway], SecondCapture);

        var entry = Assert.Single(history);
        Assert.Equal(NeighborRole.Gateway, entry.Role);
    }

    [Fact]
    public void Snapshot_describe_mentions_session_history()
    {
        var snapshot = new NetworkEnvironmentSnapshot
        {
            TakenAtUtc = FirstCapture,
            NeighborHistory =
            [
                new NetworkNeighborHistory { TimesSeen = 2 },
                new NetworkNeighborHistory { TimesSeen = 1, IsRandomizedMac = true }
            ]
        };

        var text = snapshot.Describe();

        Assert.Contains("В истории за сессию устройств: 2", text);
        Assert.Contains("ненадёжным для опознания адресом — 1", text);
    }
}
