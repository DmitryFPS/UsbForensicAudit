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

    [Theory]
    [InlineData(
        "_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412242109410569603146&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
        "2412242109410569603146")]
    [InlineData(
        "_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412281911546114543745&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
        "2412281911546114543745")]
    public void ParseWpdIdentity_ignores_interface_class_guid_and_returns_real_serial(
        string keyName, string expectedSerial)
    {
        var identity = UsbRegistryForensicHelpers.ParseWpdIdentity(keyName);

        Assert.Equal(expectedSerial, identity.Serial);
        Assert.DoesNotContain("53f56307", identity.Serial, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(
            $@"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\{expectedSerial}&0",
            identity.DeviceInstanceId);
    }

    [Fact]
    public void ParseWpdIdentity_gives_two_different_flash_drives_different_serials()
    {
        var first = UsbRegistryForensicHelpers.ParseWpdIdentity(
            "_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412242109410569603146&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}");
        var second = UsbRegistryForensicHelpers.ParseWpdIdentity(
            "_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412281911546114543745&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}");

        Assert.NotEqual(first.Serial, second.Serial);
        Assert.NotEqual(first.DeviceInstanceId, second.DeviceInstanceId);
    }

    [Fact]
    public void ParseWpdIdentity_extracts_backing_device_from_wpdbusenum_node()
    {
        var identity = UsbRegistryForensicHelpers.ParseWpdIdentity(
            @"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412242109410569603146&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}");

        Assert.StartsWith(@"SWD\WPDBUSENUM\", identity.DeviceInstanceId, StringComparison.Ordinal);
        Assert.Equal("2412242109410569603146", identity.Serial);
        Assert.Equal(
            @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            identity.BackingDeviceInstanceId);
    }

    [Fact]
    public void ParseWpdIdentity_reads_phone_mtp_key()
    {
        var identity = UsbRegistryForensicHelpers.ParseWpdIdentity(
            "_??_USB#VID_2717&PID_FF40#8dde262e#{6ac27878-a6fa-4155-ba85-f98f491d4f33}");

        Assert.Equal(@"USB\VID_2717&PID_FF40\8dde262e", identity.DeviceInstanceId);
        Assert.Equal("8dde262e", identity.Serial);
    }

    [Theory]
    [InlineData("3512837709", "D161A64D")]
    [InlineData("0xD16CE60D", "D16CE60D")]
    [InlineData("D16C-E60D", "D16CE60D")]
    [InlineData("", "")]
    [InlineData("не число", "")]
    public void Volume_serial_is_normalized_to_one_form(string raw, string expected)
    {
        Assert.Equal(expected, UsbRegistryCollector.NormalizeVolumeSerial(raw));
    }

    [Fact]
    public void ReadyBoost_key_gives_volume_label_and_serial_for_a_flash_drive()
    {
        var parsed = UsbRegistryForensicHelpers.TryParseReadyBoostKey(
            "_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412242109410569603146&0"
            + "#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}JINNLIVEUSB_3512837709",
            out var instanceId, out var label, out var volumeSerial);

        Assert.True(parsed);
        Assert.Equal(
            @"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0",
            instanceId);
        Assert.Equal("JINNLIVEUSB", label);
        Assert.Equal(3512837709u.ToString("X8"), volumeSerial);
    }

    [Fact]
    public void ReadyBoost_key_without_a_volume_label_still_yields_the_device()
    {
        var parsed = UsbRegistryForensicHelpers.TryParseReadyBoostKey(
            "_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412281911546114543745&0"
            + "#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}_1234567890",
            out var instanceId, out var label, out var volumeSerial);

        Assert.True(parsed);
        Assert.Equal("", label);
        Assert.EndsWith(@"2412281911546114543745&0", instanceId, StringComparison.Ordinal);
        Assert.Equal(1234567890u.ToString("X8"), volumeSerial);
    }

    [Fact]
    public void Unrelated_key_is_not_taken_for_a_readyboost_entry()
    {
        Assert.False(UsbRegistryForensicHelpers.TryParseReadyBoostKey(
            "WriteFilterState", out _, out _, out _));
    }

    [Theory]
    [InlineData("Device Parameters", true)]
    [InlineData("Properties", true)]
    [InlineData("LogConf", true)]
    [InlineData("Control", true)]
    [InlineData("2412242109410569603146&0", false)]
    [InlineData("_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412242109410569603146&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}", false)]
    public void Service_subkeys_of_a_device_are_not_devices(string name, bool expected)
    {
        Assert.Equal(expected, UsbRegistryCollector.IsServiceSubKey(name));
    }

    [Theory]
    [InlineData(@"SYSTEM\ControlSet001\Enum\USBSTOR", "Registry: USBSTOR", "USBSTOR")]
    [InlineData(@"SYSTEM\ControlSet001\Enum\USB", "Registry: USB", "USB")]
    [InlineData(@"SYSTEM\ControlSet001\Enum\SWD\WPDBUSENUM", "Registry: WPD/MTP", @"SWD\WPDBUSENUM")]
    public void Bus_name_comes_from_the_registry_path(string path, string source, string expected)
    {
        Assert.Equal(expected, UsbRegistryCollector.ExtractEnumPath(path, source));
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
