using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class UsbRegistryForensicHelpersTests
{
    [Fact]
    public void TryParseFileTime_reads_raw_little_endian_filetime()
    {
        var expected = new DateTimeOffset(2024, 5, 6, 7, 8, 9, TimeSpan.Zero);
        var bytes = BitConverter.GetBytes(expected.ToFileTime());

        var parsed = UsbRegistryForensicHelpers.TryParseFileTime(bytes, out var actual);

        Assert.True(parsed);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void TryParseFileTime_reads_filetime_after_devprop_header()
    {
        var expected = new DateTimeOffset(2025, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var bytes = new byte[16];
        BitConverter.GetBytes(0x10).CopyTo(bytes, 0);
        BitConverter.GetBytes(expected.ToFileTime()).CopyTo(bytes, 8);

        var parsed = UsbRegistryForensicHelpers.TryParseFileTime(bytes, out var actual);

        Assert.True(parsed);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(long.MaxValue)]
    public void TryParseFileTime_rejects_invalid_values(long value)
    {
        Assert.False(UsbRegistryForensicHelpers.TryParseFileTime(value, out _));
    }

    [Fact]
    public void SelectPnpDates_prefers_first_install_date()
    {
        var install = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var firstInstall = new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var arrival = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var removal = new DateTimeOffset(2025, 1, 2, 0, 0, 0, TimeSpan.Zero);

        var result = UsbRegistryForensicHelpers.SelectPnpDates(install, firstInstall, arrival, removal);

        Assert.Equal(firstInstall, result.FirstConnectedUtc);
        Assert.Equal(arrival, result.LastSeenUtc);
        Assert.Equal(removal, result.LastDisconnectedUtc);
        Assert.Contains("0065", result.FirstConnectedProvenance);
    }

    [Fact]
    public void BuildControlSetEnumPaths_uses_real_sets_and_ignores_alias()
    {
        var paths = UsbRegistryForensicHelpers.BuildControlSetEnumPaths(
            ["CurrentControlSet", "ControlSet002", "ControlSet001", "ControlSet001", "Select"],
            @"SWD\WPDBUSENUM");

        Assert.Equal(
            [
                @"SYSTEM\ControlSet001\Enum\SWD\WPDBUSENUM",
                @"SYSTEM\ControlSet002\Enum\SWD\WPDBUSENUM"
            ],
            paths);
    }

    [Fact]
    public void MergeRecord_combines_fields_and_preserves_best_dates()
    {
        var target = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_1234&PID_5678\ABC",
            FirstConnectedUtc = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            DateConfidence = "InstallDate (0064)",
            LastSeenUtc = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero)
        };
        var candidate = new UsbDeviceRecord
        {
            DeviceInstanceId = target.DeviceInstanceId,
            Manufacturer = "Vendor",
            FirstConnectedUtc = new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero),
            DateConfidence = "FirstInstallDate (0065)",
            LastSeenUtc = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ConnectionDisplayKind = "PnpDevProperty"
        };

        UsbRegistryForensicHelpers.MergeRecord(target, candidate);

        Assert.Equal("Vendor", target.Manufacturer);
        Assert.Equal(candidate.FirstConnectedUtc, target.FirstConnectedUtc);
        Assert.Equal(candidate.LastSeenUtc, target.LastSeenUtc);
        Assert.Equal("PnpDevProperty", target.ConnectionDisplayKind);
    }

    [Theory]
    [InlineData("USB#VID_1234&PID_5678#SERIAL", @"USB\VID_1234&PID_5678\SERIAL", "SERIAL")]
    [InlineData("SWD#WPDBUSENUM#{A-B-C}", @"SWD\WPDBUSENUM\{A-B-C}", "A-B-C")]
    public void ParseWpdIdentity_decodes_registry_key(
        string keyName,
        string expectedInstanceId,
        string expectedSerial)
    {
        var identity = UsbRegistryForensicHelpers.ParseWpdIdentity(keyName);

        Assert.Equal(expectedInstanceId, identity.DeviceInstanceId);
        Assert.Equal(expectedSerial, identity.Serial);
    }

    [Fact]
    public void IdentitiesCorrelate_matches_container_or_serial()
    {
        var usb = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_1234&PID_5678\SERIAL123",
            Serial = "SERIAL123"
        };
        var wpd = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SWD\WPDBUSENUM\{X}",
            Serial = "SERIAL123&0"
        };

        Assert.True(UsbRegistryForensicHelpers.IdentitiesCorrelate(usb, wpd));
    }

    [Fact]
    public void TimelineEnricher_does_not_replace_precise_pnp_dates_with_estimate()
    {
        var firstInstall = new DateTimeOffset(2022, 2, 3, 4, 5, 6, TimeSpan.Zero);
        var lastArrival = new DateTimeOffset(2025, 2, 3, 4, 5, 6, TimeSpan.Zero);
        var lastRemoval = new DateTimeOffset(2025, 2, 4, 4, 5, 6, TimeSpan.Zero);
        var result = new AuditResult { StartedAtUtc = DateTimeOffset.UtcNow };
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_1234&PID_5678\SERIAL",
            VisualCategory = "RealUsb",
            FirstConnectedUtc = firstInstall,
            LastSeenUtc = lastArrival,
            LastDisconnectedUtc = lastRemoval,
            ConnectionDisplayKind = "PnpDevProperty",
            DisconnectDisplayKind = "PnpDevProperty",
            DateConfidence = "Точные PnP DevProperties Windows."
        };
        result.Devices.Add(device);

        new TimelineEnricher().Enrich(result);

        Assert.Equal(firstInstall, device.FirstConnectedUtc);
        Assert.Equal(lastArrival, device.LastSeenUtc);
        Assert.Equal(lastRemoval, device.LastDisconnectedUtc);
        Assert.Equal("PnpDevProperty", device.ConnectionDisplayKind);
        Assert.Equal("PnpDevProperty", device.DisconnectDisplayKind);
    }
}
