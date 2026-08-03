using System;
using System.Linq;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Единая лента времени: слияние доказательств, очистки и сети в одну
/// хронологию, подсветка подозрительной очистки и предикат фильтрации.
/// </summary>
public sealed class TimelineViewBuilderTests
{
    private static AuditResult SampleResult()
    {
        var result = new AuditResult();
        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = new DateTimeOffset(2026, 5, 1, 14, 2, 0, TimeSpan.Zero),
            Source = "Реестр",
            DeviceHint = "SanDisk Cruzer",
            Summary = "Подключение носителя"
        });
        result.CleanupFindings.Add(new CleanupFinding
        {
            TimestampUtc = new DateTimeOffset(2026, 5, 1, 14, 7, 0, TimeSpan.Zero),
            Area = "Registry",
            PossibleTool = "USB Oblivion",
            Finding = "Очистка USBSTOR",
            Assessment = "Suspicious"
        });
        result.NetworkConnections.Add(new NetworkConnectionRecord
        {
            Name = "Wi-Fi Office",
            LastSeenUtc = new DateTimeOffset(2026, 5, 1, 13, 0, 0, TimeSpan.Zero)
        });
        return result;
    }

    [Fact]
    public void Merges_all_sources_newest_first()
    {
        var entries = TimelineViewBuilder.Build(SampleResult());

        Assert.Equal(3, entries.Count);
        Assert.Equal(TimelineViewBuilder.KindCleanup, entries[0].Kind);
        Assert.Equal(TimelineViewBuilder.KindEvidence, entries[1].Kind);
        Assert.Equal(TimelineViewBuilder.KindNetwork, entries[2].Kind);
    }

    [Fact]
    public void Suspicious_cleanup_is_alarmed()
    {
        var entries = TimelineViewBuilder.Build(SampleResult());

        Assert.True(entries.Single(x => x.Kind == TimelineViewBuilder.KindCleanup).IsAlarm);
        Assert.False(entries.Single(x => x.Kind == TimelineViewBuilder.KindEvidence).IsAlarm);
    }

    [Fact]
    public void Network_connection_without_time_is_skipped()
    {
        var result = new AuditResult();
        result.NetworkConnections.Add(new NetworkConnectionRecord { Name = "Без даты" });

        Assert.Empty(TimelineViewBuilder.Build(result));
    }

    [Fact]
    public void Filter_matches_kind_device_and_search()
    {
        var entries = TimelineViewBuilder.Build(SampleResult());
        var evidence = entries.Single(x => x.Kind == TimelineViewBuilder.KindEvidence);

        Assert.True(TimelineViewBuilder.Matches(evidence, null, null, null));
        Assert.True(TimelineViewBuilder.Matches(evidence, TimelineViewBuilder.KindEvidence, "SanDisk", "подключение"));
        Assert.False(TimelineViewBuilder.Matches(evidence, TimelineViewBuilder.KindCleanup, null, null));
        Assert.False(TimelineViewBuilder.Matches(evidence, null, "Kingston", null));
        Assert.False(TimelineViewBuilder.Matches(evidence, null, null, "нет такого текста"));
    }

    [Fact]
    public void Devices_list_is_distinct_and_sorted()
    {
        var entries = TimelineViewBuilder.Build(SampleResult());
        var devices = TimelineViewBuilder.Devices(entries);

        Assert.Contains("SanDisk Cruzer", devices);
        Assert.Equal(devices.OrderBy(x => x, StringComparer.OrdinalIgnoreCase), devices);
    }
}
