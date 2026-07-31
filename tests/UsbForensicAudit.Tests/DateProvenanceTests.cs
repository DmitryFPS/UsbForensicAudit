using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Дата без указания источника читается как установленный факт. Время
/// сканирования тоже наблюдение, и назвать его источником надо прямо, иначе в
/// колонке «когда подключали» стоит момент запуска программы без пояснений.
/// </summary>
public class DateProvenanceTests
{
    [Fact]
    public void Device_seen_only_at_scan_time_names_the_scan_as_the_source()
    {
        var result = BuildResult(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_048D&PID_C197\5&393a40ce&0&4",
            Source = "Live: WMI",
            IsCurrentlyConnected = true
        });

        new TimelineEnricher().Enrich(result);
        var device = result.Devices[0];

        Assert.Equal("LiveAtScan", device.ConnectionDisplayKind);
        Assert.Equal(result.StartedAtUtc, device.FirstConnectedUtc);
        Assert.Contains("сканирован", device.FirstConnectedProvenance, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("сканирован", device.LastSeenProvenance, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Estimated_disconnect_names_what_it_was_estimated_from()
    {
        var result = BuildResult(new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk\2412242109410569603146&0",
            Source = "Registry: USBSTOR",
            LastSeenUtc = new DateTimeOffset(2026, 7, 30, 18, 37, 24, TimeSpan.Zero),
            LastSeenProvenance = "Microsoft-Windows-Partition/Diagnostic | событие 1006"
        });

        new TimelineEnricher().Enrich(result);
        var device = result.Devices[0];

        Assert.Equal("LastActivityEstimate", device.DisconnectDisplayKind);
        Assert.Contains("Оценка по последней активности", device.LastDisconnectedProvenance);
        Assert.Contains("событие 1006", device.LastDisconnectedProvenance);
    }

    [Fact]
    public void Every_shown_date_has_a_source()
    {
        var result = BuildResult(
            new UsbDeviceRecord
            {
                DeviceInstanceId = @"USB\VID_17EF&PID_F006\0123456789ABCDEF",
                Source = "Live: WMI",
                IsCurrentlyConnected = true
            },
            new UsbDeviceRecord
            {
                DeviceInstanceId = @"USBSTOR\Disk&Ven_General&Prod_UDisk\2412281911546114543745&0",
                Source = "Registry: USBSTOR",
                LastSeenUtc = new DateTimeOffset(2026, 7, 29, 13, 43, 54, TimeSpan.Zero),
                LastSeenProvenance = "Microsoft-Windows-Partition/Diagnostic | событие 1006"
            });

        new TimelineEnricher().Enrich(result);

        foreach (var device in result.Devices)
        {
            AssertDateHasSource(device.FirstConnectedUtc, device.FirstConnectedProvenance, "подключение");
            AssertDateHasSource(device.LastSeenUtc, device.LastSeenProvenance, "последняя активность");
            AssertDateHasSource(device.LastDisconnectedUtc, device.LastDisconnectedProvenance, "отключение");
        }
    }

    private static void AssertDateHasSource(DateTimeOffset? date, string provenance, string label)
    {
        if (date.HasValue)
        {
            Assert.False(string.IsNullOrWhiteSpace(provenance), $"У даты «{label}» не указан источник.");
        }
    }

    private static AuditResult BuildResult(params UsbDeviceRecord[] devices)
    {
        var result = new AuditResult { StartedAtUtc = new DateTimeOffset(2026, 7, 31, 12, 40, 50, TimeSpan.Zero) };
        result.Devices.AddRange(devices);
        return result;
    }
}
