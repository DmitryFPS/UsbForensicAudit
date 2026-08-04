using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class ConnectionSessionBuilderTests
{
    private static DateTimeOffset At(int hour, int minute = 0) =>
        new(2026, 7, 27, hour, minute, 0, TimeSpan.Zero);

    [Fact]
    public void Connect_and_disconnect_form_one_closed_session()
    {
        var sessions = ConnectionSessionBuilder.Build(
        [
            (At(9), true, "Kernel-PnP 410"),
            (At(11, 30), false, "Kernel-PnP 420")
        ]);

        var session = Assert.Single(sessions);
        Assert.Equal(At(9), session.StartUtc);
        Assert.Equal(At(11, 30), session.EndUtc);
        Assert.False(session.IsOpen);
        Assert.Equal("2 ч 30 мин", session.DurationText);
    }

    [Fact]
    public void Three_connections_are_reported_as_three_sessions()
    {
        var sessions = ConnectionSessionBuilder.Build(
        [
            (At(9), true, "a"), (At(10), false, "b"),
            (At(12), true, "c"), (At(13), false, "d"),
            (At(15), true, "e"), (At(16), false, "f")
        ]);

        Assert.Equal(3, sessions.Count);
        Assert.All(sessions, x => Assert.False(x.IsOpen));
    }

    [Fact]
    public void Repeated_enumeration_within_two_minutes_is_one_session()
    {
        var sessions = ConnectionSessionBuilder.Build(
        [
            (At(9, 0), true, "arrival"),
            (At(9, 1), true, "re-enumeration"),
            (At(10, 0), false, "removal")
        ]);

        var session = Assert.Single(sessions);
        Assert.Equal(At(9, 0), session.StartUtc);
        Assert.Equal(At(10, 0), session.EndUtc);
    }

    [Fact]
    public void Session_without_removal_event_stays_open()
    {
        var sessions = ConnectionSessionBuilder.Build([(At(9), true, "arrival")]);

        var session = Assert.Single(sessions);
        Assert.True(session.IsOpen);
        Assert.Equal("не закрыт", session.DurationText);
    }

    /// <summary>
    /// Регрессия: отключение без парного подключения (журнал начался позже,
    /// чем устройство вставили) раньше выбрасывалось целиком. Терялся сам
    /// факт, что до этого момента устройство было в машине.
    /// </summary>
    [Fact]
    public void Removal_without_a_preceding_arrival_is_kept_with_unknown_start()
    {
        var sessions = ConnectionSessionBuilder.Build([(At(9), false, "removal")]);

        var session = Assert.Single(sessions);
        Assert.True(session.IsStartUnknown);
        Assert.Equal(At(9), session.EndUtc);
        Assert.Equal("removal", session.EndProvenance);
        Assert.Equal("начало неизвестно", session.DurationText);
        Assert.Null(session.Duration);
    }

    [Fact]
    public void Enricher_fills_sessions_from_evidence()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            Serial = "2412242109410569603146",
            VisualCategory = "RealUsb"
        };
        var result = new AuditResult
        {
            Devices = { device },
            Evidence =
            {
                Evidence(At(9), "Подключение устройства", "Microsoft-Windows-Kernel-PnP/Configuration", "410"),
                Evidence(At(11), "Отключение устройства", "Microsoft-Windows-Kernel-PnP/Configuration", "420")
            }
        };

        new TimelineEnricher().Enrich(result);

        var session = Assert.Single(device.Sessions);
        Assert.Equal(At(9), session.StartUtc);
        Assert.Equal(At(11), session.EndUtc);
        Assert.Contains("410", session.StartProvenance, StringComparison.Ordinal);
        Assert.Contains("420", session.EndProvenance, StringComparison.Ordinal);
    }

    private static EvidenceRecord Evidence(
        DateTimeOffset timestamp, string category, string source, string eventId) => new()
        {
            TimestampUtc = timestamp,
            Source = source,
            EventId = eventId,
            EvidenceCategory = category,
            DeviceHint = @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            CanEstablishConnectionDate = true
        };
}
