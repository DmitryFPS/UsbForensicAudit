using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class EventChannelStateTests
{
    private static readonly DateTimeOffset Moment = new(2026, 7, 27, 6, 39, 0, TimeSpan.Zero);

    [Fact]
    public void Missing_channel_cannot_support_a_conclusion()
    {
        var state = new EventChannelState { Channel = "Microsoft-Windows-Partition/Diagnostic", Exists = false };

        Assert.False(state.AbsenceIsMeaningful(Moment));
        Assert.Contains("отсутствует", state.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void Disabled_channel_cannot_support_a_conclusion()
    {
        var state = new EventChannelState
        {
            Channel = "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
            Exists = true,
            IsEnabled = false
        };

        Assert.False(state.AbsenceIsMeaningful(Moment));
        Assert.Contains("выключен", state.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void Channel_that_starts_after_the_moment_cannot_support_a_conclusion()
    {
        var state = new EventChannelState
        {
            Channel = "System",
            Exists = true,
            IsEnabled = true,
            OldestRecordUtc = Moment.AddDays(1)
        };

        Assert.False(state.AbsenceIsMeaningful(Moment));
    }

    [Fact]
    public void Healthy_channel_covering_the_moment_supports_a_conclusion()
    {
        var state = new EventChannelState
        {
            Channel = "System",
            Exists = true,
            IsEnabled = true,
            RecordCount = 40000,
            OldestRecordUtc = Moment.AddDays(-30)
        };

        Assert.True(state.AbsenceIsMeaningful(Moment));
        Assert.Contains("включён", state.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void Full_channel_is_reported_as_wrapping()
    {
        var state = new EventChannelState
        {
            Channel = "Security",
            Exists = true,
            IsEnabled = true,
            MaximumSizeBytes = 20_971_520,
            FileSizeBytes = 20_900_000,
            OldestRecordUtc = Moment.AddDays(-1)
        };

        Assert.True(state.IsLikelyWrapped);
        Assert.Contains("по кругу", state.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void Read_error_is_carried_into_the_explanation()
    {
        var state = new EventChannelState
        {
            Channel = "Security",
            Exists = true,
            IsEnabled = true,
            Error = "Отказано в доступе"
        };

        Assert.False(state.AbsenceIsMeaningful(Moment));
        Assert.Contains("Отказано в доступе", state.Describe(), StringComparison.Ordinal);
    }
}
