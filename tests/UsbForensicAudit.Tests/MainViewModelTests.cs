using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class MainViewModelTests
{
    [Theory]
    [InlineData("RealUsb", 0)]
    [InlineData("RelatedStorage", 1)]
    [InlineData("SupportArtifact", 2)]
    [InlineData("Unknown", 3)]
    [InlineData("что-то ещё", 3)]
    public void CategoryRank_ranks_known_categories_ahead_of_unknown(string category, int expected)
    {
        Assert.Equal(expected, MainViewModel.CategoryRank(category));
    }

    [Theory]
    [InlineData("Critical", 5)]
    [InlineData("High", 4)]
    [InlineData("Medium", 3)]
    [InlineData("Low", 2)]
    [InlineData("Info", 1)]
    [InlineData("прочее", 0)]
    public void SeverityRank_is_case_insensitive_and_orders_by_severity(string severity, int expected)
    {
        Assert.Equal(expected, MainViewModel.SeverityRank(severity));
    }

    [Fact]
    public void OrderDevices_sorts_by_category_then_display_name()
    {
        var input = new[]
        {
            new UsbDeviceRecord { VisualCategory = "SupportArtifact", FriendlyName = "A-support" },
            new UsbDeviceRecord { VisualCategory = "RealUsb", FriendlyName = "Zeta" },
            new UsbDeviceRecord { VisualCategory = "RealUsb", FriendlyName = "Alpha" },
            new UsbDeviceRecord { VisualCategory = "RelatedStorage", FriendlyName = "B-storage" },
        };

        var ordered = MainViewModel.OrderDevices(input).ToList();

        Assert.Equal("Alpha", ordered[0].FriendlyName);
        Assert.Equal("Zeta", ordered[1].FriendlyName);
        Assert.Equal("B-storage", ordered[2].FriendlyName);
        Assert.Equal("A-support", ordered[3].FriendlyName);
    }

    [Fact]
    public void OrderEvidence_returns_newest_first()
    {
        var older = new EvidenceRecord { TimestampUtc = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero) };
        var newer = new EvidenceRecord { TimestampUtc = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero) };

        var ordered = MainViewModel.OrderEvidence(new[] { older, newer }).ToList();

        Assert.Same(newer, ordered[0]);
        Assert.Same(older, ordered[1]);
    }

    [Fact]
    public void OrderCleanupFindings_puts_suspicious_then_higher_severity_then_newer_first()
    {
        var benignCritical = new CleanupFinding
        {
            Assessment = "Benign",
            Severity = "Critical",
            TimestampUtc = new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero),
        };
        var suspiciousLowOld = new CleanupFinding
        {
            Assessment = "Suspicious",
            Severity = "Low",
            TimestampUtc = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero),
        };
        var suspiciousHigh = new CleanupFinding
        {
            Assessment = "Suspicious",
            Severity = "High",
            TimestampUtc = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero),
        };
        var suspiciousLowNew = new CleanupFinding
        {
            Assessment = "Suspicious",
            Severity = "Low",
            TimestampUtc = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
        };

        var ordered = MainViewModel
            .OrderCleanupFindings(new[] { benignCritical, suspiciousLowOld, suspiciousHigh, suspiciousLowNew })
            .ToList();

        Assert.Same(suspiciousHigh, ordered[0]);
        Assert.Same(suspiciousLowNew, ordered[1]);
        Assert.Same(suspiciousLowOld, ordered[2]);
        Assert.Same(benignCritical, ordered[3]);
    }
}
