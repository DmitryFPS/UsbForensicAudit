using System.Buffers.Binary;
using System.Globalization;
using System.Security;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class MaturityCoverageParserTests
{
    private static readonly byte[] LinkClsid =
    [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    ];

    [Fact]
    public void ShellLink_parses_id_list_unicode_paths_volume_and_filetimes()
    {
        var created = new DateTimeOffset(2023, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var accessed = new DateTimeOffset(2024, 2, 3, 4, 5, 6, TimeSpan.Zero);
        var written = new DateTimeOffset(2025, 3, 4, 5, 6, 7, TimeSpan.Zero);
        var bytes = BuildShellLink(
            localPath: @"E:\Сбор",
            suffix: @"Case\report.txt",
            volumeLabel: "USB_DISK",
            volumeSerial: 0xA1B2C3D4,
            withIdList: true,
            created,
            accessed,
            written);

        var parsed = ShellLinkParser.TryParse(bytes, "fixture.lnk");

        Assert.NotNull(parsed);
        Assert.Equal("fixture.lnk", parsed!.LinkPath);
        Assert.Equal(@"E:\Сбор", parsed.LocalBasePath);
        Assert.Equal(@"Case\report.txt", parsed.CommonPathSuffix);
        Assert.Equal(@"E:\Сбор\Case\report.txt", parsed.BestTarget);
        Assert.Equal("USB_DISK", parsed.VolumeLabel);
        Assert.Equal("A1B2C3D4", parsed.VolumeSerialNumber);
        Assert.Equal(created, parsed.CreationTimeUtc);
        Assert.Equal(accessed, parsed.AccessTimeUtc);
        Assert.Equal(written, parsed.WriteTimeUtc);
    }

    [Theory]
    [MemberData(nameof(InvalidShellLinks))]
    public void ShellLink_rejects_invalid_header_and_clsid(byte[] bytes)
    {
        Assert.Null(ShellLinkParser.TryParse(bytes, "broken.lnk"));
    }

    public static TheoryData<byte[]> InvalidShellLinks()
    {
        var wrongSize = BuildShellLink();
        BinaryPrimitives.WriteUInt32LittleEndian(wrongSize, 0x4D);
        var wrongClsid = BuildShellLink();
        wrongClsid[4] ^= 0xFF;
        return new TheoryData<byte[]>
        {
            Array.Empty<byte>(),
            new byte[0x4B],
            wrongSize,
            wrongClsid
        };
    }

    [Fact]
    public void ShellLink_survives_truncated_id_list_and_invalid_filetimes_without_inventing_metadata()
    {
        var bytes = BuildShellLink();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x14, 4), 0x3);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x4C, 2), ushort.MaxValue);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(0x1C, 8), long.MaxValue);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(0x24, 8), -1);

        var parsed = ShellLinkParser.TryParse(bytes, "truncated-id-list.lnk");

        Assert.NotNull(parsed);
        Assert.Equal("", parsed!.LocalBasePath);
        Assert.Equal("", parsed.CommonPathSuffix);
        Assert.Null(parsed.CreationTimeUtc);
        Assert.Null(parsed.AccessTimeUtc);
    }

    [Fact]
    public void ShellLink_ignores_out_of_bounds_link_info_and_combines_partial_targets_safely()
    {
        var bytes = BuildShellLink();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x4C, 4), uint.MaxValue);

        var parsed = ShellLinkParser.TryParse(bytes, "bad-link-info.lnk");

        Assert.NotNull(parsed);
        Assert.Equal("", parsed!.BestTarget);
        Assert.Equal("only-right", new ShellLinkInfo { CommonPathSuffix = "only-right" }.BestTarget);
        Assert.Equal("only-left", new ShellLinkInfo { LocalBasePath = "only-left" }.BestTarget);
        Assert.Equal(@"E:\folder\child.txt",
            new ShellLinkInfo { LocalBasePath = "E:/folder/", CommonPathSuffix = "/child.txt" }.BestTarget);
    }

    [Fact]
    public void MruListEx_ignores_negative_duplicates_partial_tail_and_non_binary_values()
    {
        var bytes = new byte[19];
        WriteInt32(bytes, 0, 5);
        WriteInt32(bytes, 4, -2);
        WriteInt32(bytes, 8, 5);
        WriteInt32(bytes, 12, 7);
        bytes[16] = 0xAA;

        Assert.Equal([5, 7], ForensicArtifactParsers.ParseMruListEx(bytes));
        Assert.Empty(ForensicArtifactParsers.ParseMruListEx("5,7"));
        Assert.Empty(ForensicArtifactParsers.ParseMruListEx(null));
    }

    [Fact]
    public void Pidl_falls_back_to_raw_strings_after_malformed_item_and_extracts_volume_guid()
    {
        const string guid = "11111111-2222-3333-4444-555555555555";
        var raw = Encoding.ASCII.GetBytes($@"X:\Case\\?\Volume{{{guid}}}\evidence");
        var bytes = new byte[raw.Length + 2];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, checked((ushort)(bytes.Length + 10)));
        raw.CopyTo(bytes, 2);

        var parsed = ForensicArtifactParsers.ParsePidl(bytes);

        Assert.Contains(@"X:\Case", parsed.BestPath, StringComparison.OrdinalIgnoreCase);
        Assert.Equal($@"\\?\Volume{{{guid}}}", parsed.VolumeGuid);
        Assert.Empty(ForensicArtifactParsers.ParsePidl(null).PathFragments);
        Assert.Empty(ForensicArtifactParsers.ParsePidl([1]).PathFragments);
    }

    [Fact]
    public void ShellBag_joins_parent_and_fragment_and_recognizes_supported_removable_markers()
    {
        var node = ForensicArtifactParsers.ParseShellBagNode(
            BuildPidlItem(@"removable\Photos"), @"Root\", 12);

        Assert.Equal(@"Root\removable\Photos", node.Path);
        Assert.True(node.IsUsbRelevant);
        Assert.True(ForensicArtifactParsers.IsUsbOrVolumeMarker(@"SWD\WPDBUSENUM\phone"));
        Assert.True(ForensicArtifactParsers.IsUsbOrVolumeMarker(@"\\?\Volume{11111111-2222-3333-4444-555555555555}"));
        Assert.False(ForensicArtifactParsers.IsUsbOrVolumeMarker(@"C:\Windows"));
    }

    [Fact]
    public void CustomJumpList_skips_false_headers_and_splits_adjacent_valid_links()
    {
        var first = BuildShellLink(created: new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var second = BuildShellLink(created: new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var data = new byte[7 + first.Length + 3 + second.Length];
        data[0] = 0x4C; // Not a complete Shell Link header.
        first.CopyTo(data, 7);
        second.CopyTo(data, 7 + first.Length + 3);

        var entries = ForensicArtifactParsers.ParseCustomJumpList(data, "custom-app");

        Assert.Equal(2, entries.Count);
        Assert.Equal("7", entries[0].StreamName);
        Assert.Equal((7 + first.Length + 3).ToString("X", CultureInfo.InvariantCulture), entries[1].StreamName);
        Assert.All(entries, entry => Assert.Null(entry.EntryTimestampUtc));
    }

    [Fact]
    public void AutomaticJumpList_rejects_truncated_and_structurally_invalid_compound_files()
    {
        var truncated = new byte[512];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(truncated, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(truncated.AsSpan(0x1E, 2), 15);
        BinaryPrimitives.WriteUInt16LittleEndian(truncated.AsSpan(0x20, 2), 6);

        Assert.Empty(ForensicArtifactParsers.ParseAutomaticJumpList(new byte[511], "app"));
        Assert.Empty(ForensicArtifactParsers.ParseAutomaticJumpList(truncated, "app"));
    }

    [Fact]
    public void AutomaticJumpList_correlates_dest_list_stream_number_with_filetime()
    {
        var expected = new DateTimeOffset(2024, 8, 9, 10, 11, 12, TimeSpan.Zero);

        var entry = Assert.Single(ForensicArtifactParsers.ParseAutomaticJumpList(
            BuildAutomaticJumpList(expected), "automatic-app"));

        Assert.Equal("1", entry.StreamName);
        Assert.Equal(expected, entry.EntryTimestampUtc);
        Assert.Equal("automatic-app:1", entry.Link.LinkPath);
    }

    [Fact]
    public void Shimcache_skips_malformed_entry_then_parses_valid_unc_entry_without_implausible_filetime()
    {
        var valid = BuildShimcacheEntry(@"\\server\usb\tool.exe", fileTime: 1);
        var bytes = new byte[16 + valid.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, 0x73743031);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8, 4), 9);
        valid.CopyTo(bytes, 16);

        var parsed = ForensicArtifactParsers.ParseShimcache(bytes);

        Assert.True(parsed.Supported);
        var entry = Assert.Single(parsed.Entries);
        Assert.Equal(@"\\server\usb\tool.exe", entry.Path);
        Assert.Null(entry.LastModifiedUtc);
        Assert.False(entry.ExecutionProven);
    }

    [Fact]
    public void Shimcache_rejects_empty_oversized_odd_and_non_windows_entries()
    {
        Assert.False(ForensicArtifactParsers.ParseShimcache(null).Supported);
        Assert.Contains("truncated", ForensicArtifactParsers.ParseShimcache(new byte[15]).Warning,
            StringComparison.OrdinalIgnoreCase);

        var oversized = new byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(oversized, 0x73743031);
        BinaryPrimitives.WriteUInt32LittleEndian(oversized.AsSpan(8, 4), 1_048_577);
        Assert.False(ForensicArtifactParsers.ParseShimcache(oversized).Supported);

        Assert.False(ForensicArtifactParsers.ParseShimcache(BuildShimcacheEntry("relative.exe")).Supported);
        Assert.False(ForensicArtifactParsers.ParseShimcache(BuildShimcacheEntry(@"C:\bad.exe", oddPathLength: true)).Supported);
    }

    [Theory]
    [InlineData("<not-xml")]
    [InlineData("<Event><EventData /></Event>")]
    [InlineData("<Event><System><EventID>NaN</EventID><TimeCreated SystemTime=\"2026-01-01Z\" /></System></Event>")]
    [InlineData("<Event><System><EventID>1</EventID><TimeCreated SystemTime=\"not-a-date\" /></System></Event>")]
    public void EventXml_rejects_malformed_or_incomplete_system_data(string xml)
    {
        Assert.False(EventLogRecordParser.TryParse(xml, out var parsed));
        Assert.Null(parsed);
    }

    [Fact]
    public void EventXml_collects_duplicate_named_data_and_user_data_leaves()
    {
        var xml = """
                  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                      <Provider Name="Microsoft-Windows-Kernel-PnP" />
                      <EventID>411</EventID>
                      <EventRecordID>bad-record-id</EventRecordID>
                      <TimeCreated SystemTime="2026-06-01T10:00:00+03:00" />
                      <Channel>System</Channel><Computer>HOST</Computer>
                    </System>
                    <EventData>
                      <Data Name="DevicePath"> USB\VID_1234&amp;PID_5678\ONE </Data>
                      <Data Name="DevicePath">USB\VID_1234&amp;PID_5678\TWO</Data>
                      <Data Name="">ignored</Data><Data Name="Blank"> </Data>
                    </EventData>
                    <UserData><Payload><DeviceName>WPD phone</DeviceName><Nested><State>Ready</State></Nested></Payload></UserData>
                  </Event>
                  """;

        Assert.True(EventLogRecordParser.TryParse(xml, out var parsed));

        Assert.Null(parsed!.RecordId);
        Assert.Equal(new DateTimeOffset(2026, 6, 1, 7, 0, 0, TimeSpan.Zero), parsed.TimestampUtc);
        Assert.Equal(@"USB\VID_1234&PID_5678\ONE", parsed.Fields["DevicePath"]);
        Assert.Equal(@"USB\VID_1234&PID_5678\TWO", parsed.Fields["DevicePath#2"]);
        Assert.Equal("WPD phone", parsed.Fields["DeviceName"]);
        Assert.Equal("Ready", parsed.Fields["State"]);
        Assert.False(parsed.Fields.ContainsKey("Blank"));
    }

    [Fact]
    public void EventEvidence_prefers_named_device_field_and_preserves_level()
    {
        var longDevice = @"USB\VID_1234&PID_5678\" + new string('S', 600);
        Assert.True(EventLogRecordParser.TryParse(
            EventXml("Microsoft-Windows-Kernel-PnP", 411,
                ("Other", @"prefix WPD\phone"),
                ("Level", "Error"),
                ("DeviceInstanceId", longDevice)),
            out var parsed));

        var evidence = EventLogRecordParser.ToEvidence(parsed!);

        Assert.NotNull(evidence);
        Assert.Equal(500, evidence!.DeviceHint.Length);
        Assert.StartsWith(@"USB\VID_1234&PID_5678\", evidence.DeviceHint, StringComparison.Ordinal);
        Assert.Equal("Error", evidence.Level);
        Assert.Contains(evidence.DeviceHint, evidence.Summary, StringComparison.Ordinal);
        Assert.Equal("Ошибка запуска PnP-устройства", evidence.EvidenceCategory);
    }

    [Fact]
    public void EventEvidence_extracts_earliest_marked_text_and_flattens_line_endings()
    {
        Assert.True(EventLogRecordParser.TryParse(
            EventXml("Some-Provider", 77, ("Message", "prefix WPD\r\nphone then USB\\later")),
            out var parsed));

        var evidence = EventLogRecordParser.ToEvidence(parsed!);

        Assert.NotNull(evidence);
        Assert.Equal(@"WPD phone then USB\later", evidence!.DeviceHint);
        Assert.Equal("Событие PnP/драйвера устройства", evidence.EvidenceCategory);
        Assert.Equal("Corroborating", evidence.EvidenceStrength);
        Assert.False(evidence.CanEstablishConnectionDate);
    }

    [Fact]
    public void EventEvidence_uses_message_fallback_for_always_relevant_log_clear_event()
    {
        Assert.True(EventLogRecordParser.TryParse(
            EventXml("Microsoft-Windows-Eventlog", 104),
            out var parsed));

        var evidence = EventLogRecordParser.ToEvidence(parsed!, "notice\r\nUSBSTOR\\Disk&Ven_Test\\SERIAL");

        Assert.NotNull(evidence);
        Assert.Equal(@"USBSTOR\Disk&Ven_Test\SERIAL", evidence!.DeviceHint);
        Assert.Equal("Очистка журнала", evidence.EvidenceCategory);
        Assert.Equal("Direct", evidence.EvidenceStrength);
        Assert.Equal("High", evidence.Confidence);
        Assert.Contains("зачистки", evidence.UserExplanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EventEvidence_builds_named_field_then_first_line_summaries_when_no_device_hint_exists()
    {
        Assert.True(EventLogRecordParser.TryParse(
            EventXml("Microsoft-Windows-Security-Auditing", 1102, ("Subject", "Auditor")),
            out var withField));
        Assert.True(EventLogRecordParser.TryParse(
            EventXml("Microsoft-Windows-Security-Auditing", 1102),
            out var withoutFields));

        var namedSummary = EventLogRecordParser.ToEvidence(withField!)!.Summary;
        var messageSummary = EventLogRecordParser.ToEvidence(withoutFields!, "first line\nsecond line")!.Summary;

        Assert.Contains("Subject=Auditor", namedSummary);
        Assert.Equal("first line", messageSummary);
    }

    [Theory]
    [InlineData("Microsoft-Windows-Storage-ClassPnP", 510, "Отключение/удаление устройства", true)]
    [InlineData("Microsoft-Windows-Storage-ClassPnP", 600, "Подключение/инициализация устройства", false)]
    [InlineData("Microsoft-Windows-WPD-MTPClassDriver", 1001, "Событие MTP/WPD-устройства", false)]
    public void EventClassifier_handles_storage_and_wpd_lifecycle_boundaries(
        string provider, int eventId, string category, bool establishesDate)
    {
        Assert.True(EventLogRecordParser.TryParse(
            EventXml(provider, eventId, ("DeviceId", @"USB\VID_1234&PID_5678\SERIAL")),
            out var parsed));

        var evidence = EventLogRecordParser.ToEvidence(parsed!);

        Assert.NotNull(evidence);
        Assert.Equal(category, evidence!.EvidenceCategory);
        Assert.Equal(establishesDate, evidence.CanEstablishConnectionDate);
    }

    [Fact]
    public void FileTime_parser_accepts_supported_scalar_string_and_header_encodings()
    {
        var expected = new DateTimeOffset(2024, 5, 6, 7, 8, 9, TimeSpan.Zero);
        var fileTime = expected.ToFileTime();
        var hex = fileTime.ToString("X16", CultureInfo.InvariantCulture);
        var prefixedBytes = new byte[12];
        BitConverter.GetBytes(fileTime).CopyTo(prefixedBytes, 4);

        AssertParsedFileTime(expected, expected.UtcDateTime);
        AssertParsedFileTime(expected, expected.ToOffset(TimeSpan.FromHours(3)));
        AssertParsedFileTime(expected, fileTime);
        AssertParsedFileTime(expected, checked((ulong)fileTime));
        AssertParsedFileTime(expected, fileTime.ToString(CultureInfo.InvariantCulture));
        AssertParsedFileTime(expected, $"0x{hex[..8]}-{hex[8..]}");
        AssertParsedFileTime(expected, "2024-05-06T07:08:09Z");
        AssertParsedFileTime(expected, prefixedBytes);
    }

    [Theory]
    [MemberData(nameof(InvalidFileTimes))]
    public void FileTime_parser_rejects_unsupported_implausible_and_truncated_values(object? value)
    {
        Assert.False(UsbRegistryForensicHelpers.TryParseFileTime(value, out _));
    }

    public static TheoryData<object?> InvalidFileTimes() =>
        new()
        {
            null,
            true,
            0,
            ulong.MaxValue,
            new byte[7],
            new byte[16],
            "not a date",
            "1989-12-31T23:59:59Z",
            DateTimeOffset.UtcNow.AddDays(3)
        };

    [Fact]
    public void ControlSet_paths_filter_sort_deduplicate_and_fall_back_when_no_real_set_exists()
    {
        var paths = UsbRegistryForensicHelpers.BuildControlSetEnumPaths(
            ["ControlSet010", "controlset002", "ControlSet002", "ControlSet2", "CurrentControlSet"],
            @"USBSTOR");

        Assert.Equal(
            [@"SYSTEM\controlset002\Enum\USBSTOR", @"SYSTEM\ControlSet010\Enum\USBSTOR"],
            paths);
        Assert.Equal(
            [@"SYSTEM\CurrentControlSet\Enum\USB"],
            UsbRegistryForensicHelpers.BuildControlSetEnumPaths(["Select", "ControlSet01"], "USB"));
    }

    [Theory]
    [InlineData(@"prefix#USB#VID_1234%26PID_5678#SERIAL%260", @"USB\VID_1234&PID_5678\SERIAL&0", "SERIAL")]
    [InlineData(@"prefix#SWD#WPDBUSENUM#PHONE%260", @"SWD\WPDBUSENUM\PHONE&0", "PHONE")]
    [InlineData(@"unstructured%20name", "unstructured name", "")]
    public void Wpd_identity_decodes_embedded_ids_and_normalizes_serial_suffix(
        string key, string instanceId, string serial)
    {
        var parsed = UsbRegistryForensicHelpers.ParseWpdIdentity(key);

        Assert.Equal(instanceId, parsed.DeviceInstanceId);
        Assert.Equal(serial, parsed.Serial);
    }

    [Fact]
    public void MergeRecord_preserves_existing_identity_merges_sets_volumes_dates_and_precision()
    {
        var oldVolume = new VolumeIdentity { MappingName = "Volume{A}", Source = "MountedDevices" };
        var duplicate = new VolumeIdentity { MappingName = "volume{a}", Source = "mounteddevices" };
        var newVolume = new VolumeIdentity { MappingName = "Volume{B}", Source = "WPD" };
        var target = new UsbDeviceRecord
        {
            Source = "USBSTOR; Existing",
            FriendlyName = "Keep me",
            HardwareIds = "USB\\A",
            DriveLetters = "E:",
            FirstConnectedUtc = Utc(2020, 1, 1),
            LastSeenUtc = Utc(2024, 1, 1),
            LastDisconnectedUtc = Utc(2024, 2, 1),
            RegistryLastWriteUtc = Utc(2024, 3, 1),
            DateConfidence = "InstallDate (0064)",
            ConnectionDisplayKind = "ExactEvent",
            DisconnectDisplayKind = "LastActivityEstimate",
            Volumes = [oldVolume]
        };
        var candidate = new UsbDeviceRecord
        {
            Source = "usbstor; WPD",
            FriendlyName = "Do not replace",
            Manufacturer = "Vendor",
            HardwareIds = "usb\\a; USB\\B",
            DriveLetters = "E:; F:",
            FirstConnectedUtc = Utc(2022, 1, 1),
            LastSeenUtc = Utc(2025, 1, 1),
            LastDisconnectedUtc = Utc(2023, 1, 1),
            RegistryLastWriteUtc = Utc(2025, 3, 1),
            DateConfidence = "FirstInstallDate (0065)",
            ConnectionDisplayKind = "RegistryActivity",
            DisconnectDisplayKind = "PnpDevProperty",
            IsCurrentlyConnected = true,
            Volumes = [duplicate, newVolume]
        };

        UsbRegistryForensicHelpers.MergeRecord(target, candidate);

        Assert.Equal("USBSTOR; Existing; WPD", target.Source);
        Assert.Equal("Keep me", target.FriendlyName);
        Assert.Equal("Vendor", target.Manufacturer);
        Assert.Equal(@"USB\A; USB\B", target.HardwareIds);
        Assert.Equal("E:; F:", target.DriveLetters);
        Assert.Equal(2, target.Volumes.Count);
        Assert.Equal(candidate.FirstConnectedUtc, target.FirstConnectedUtc);
        Assert.Equal(candidate.LastSeenUtc, target.LastSeenUtc);
        Assert.Equal(Utc(2024, 2, 1), target.LastDisconnectedUtc);
        Assert.Equal(candidate.RegistryLastWriteUtc, target.RegistryLastWriteUtc);
        Assert.Equal("ExactEvent", target.ConnectionDisplayKind);
        Assert.Equal("PnpDevProperty", target.DisconnectDisplayKind);
        Assert.True(target.IsCurrentlyConnected);
    }

    [Fact]
    public void MergeRecord_keeps_first_install_date_over_older_lower_confidence_candidate()
    {
        var target = new UsbDeviceRecord
        {
            FirstConnectedUtc = Utc(2022, 1, 1),
            DateConfidence = "FirstInstallDate (0065)"
        };
        var candidate = new UsbDeviceRecord
        {
            FirstConnectedUtc = Utc(2010, 1, 1),
            DateConfidence = "InstallDate (0064)"
        };

        UsbRegistryForensicHelpers.MergeRecord(target, candidate);

        Assert.Equal(Utc(2022, 1, 1), target.FirstConnectedUtc);
    }

    [Fact]
    public void Date_selection_reports_install_fallback_and_absent_provenance()
    {
        var install = Utc(2021, 2, 3);

        var selected = UsbRegistryForensicHelpers.SelectPnpDates(install, null, null, null);
        var empty = UsbRegistryForensicHelpers.SelectPnpDates(null, null, null, null);

        Assert.Equal(install, selected.FirstConnectedUtc);
        Assert.Equal("InstallDate (0064)", selected.FirstConnectedProvenance);
        Assert.Equal("", selected.LastSeenProvenance);
        Assert.Equal("", selected.LastDisconnectedProvenance);
        Assert.Null(empty.FirstConnectedUtc);
        Assert.Equal("", empty.FirstConnectedProvenance);
    }

    [Fact]
    public void Identity_correlation_checks_instance_container_then_hardware_serial()
    {
        Assert.True(UsbRegistryForensicHelpers.IdentitiesCorrelate(
            new UsbDeviceRecord { DeviceInstanceId = @"USB\ABC" },
            new UsbDeviceRecord { DeviceInstanceId = @"usb\abc" }));
        Assert.True(UsbRegistryForensicHelpers.IdentitiesCorrelate(
            new UsbDeviceRecord { ContainerId = "{A}" },
            new UsbDeviceRecord { ContainerId = "{a}" }));
        Assert.True(UsbRegistryForensicHelpers.IdentitiesCorrelate(
            new UsbDeviceRecord { Serial = "SERIAL-123" },
            new UsbDeviceRecord { Serial = "{serial-123&0}" }));
        Assert.False(UsbRegistryForensicHelpers.IdentitiesCorrelate(
            new UsbDeviceRecord { Serial = "00000000" },
            new UsbDeviceRecord { Serial = "00000000" }));
    }

    private static byte[] BuildShellLink(
        string localPath = @"E:\Case",
        string suffix = "report.txt",
        string volumeLabel = "USB",
        uint volumeSerial = 0x12345678,
        bool withIdList = false,
        DateTimeOffset? created = null,
        DateTimeOffset? accessed = null,
        DateTimeOffset? written = null)
    {
        var linkInfoOffset = 0x4C + (withIdList ? 6 : 0);
        var data = new byte[1024];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 0x4C);
        LinkClsid.CopyTo(data, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x14, 4), withIdList ? 0x3u : 0x2u);
        WriteFileTime(data, 0x1C, created);
        WriteFileTime(data, 0x24, accessed);
        WriteFileTime(data, 0x2C, written);
        if (withIdList)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x4C, 2), 4);
            data.AsSpan(0x4E, 4).Fill(0xCC);
        }

        const int headerSize = 0x24;
        const int volumeOffset = headerSize;
        const int volumeSize = 0x20;
        var cursor = volumeOffset + volumeSize;
        var ansiLocalOffset = cursor;
        cursor += WriteString(data, linkInfoOffset + cursor, localPath, Encoding.Latin1);
        var ansiSuffixOffset = cursor;
        cursor += WriteString(data, linkInfoOffset + cursor, suffix, Encoding.Latin1);
        var unicodeLocalOffset = cursor;
        cursor += WriteString(data, linkInfoOffset + cursor, localPath, Encoding.Unicode);
        var unicodeSuffixOffset = cursor;
        cursor += WriteString(data, linkInfoOffset + cursor, suffix, Encoding.Unicode);

        var info = data.AsSpan(linkInfoOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(info, checked((uint)cursor));
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(4, 4), headerSize);
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(8, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(12, 4), volumeOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(16, 4), checked((uint)ansiLocalOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(24, 4), checked((uint)ansiSuffixOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(28, 4), checked((uint)unicodeLocalOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(32, 4), checked((uint)unicodeSuffixOffset));

        var volume = info.Slice(volumeOffset, volumeSize);
        BinaryPrimitives.WriteUInt32LittleEndian(volume, volumeSize);
        BinaryPrimitives.WriteUInt32LittleEndian(volume.Slice(8, 4), volumeSerial);
        BinaryPrimitives.WriteUInt32LittleEndian(volume.Slice(12, 4), 0x10);
        WriteString(data, linkInfoOffset + volumeOffset + 0x10, volumeLabel, Encoding.Latin1);

        Array.Resize(ref data, linkInfoOffset + cursor);
        return data;
    }

    private static byte[] BuildPidlItem(string value)
    {
        var payload = Encoding.Unicode.GetBytes(value + "\0");
        var bytes = new byte[payload.Length + 4];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, checked((ushort)(payload.Length + 2)));
        payload.CopyTo(bytes, 2);
        return bytes;
    }

    private static byte[] BuildAutomaticJumpList(DateTimeOffset timestamp)
    {
        const uint free = 0xFFFFFFFF;
        const uint end = 0xFFFFFFFE;
        var data = new byte[2560];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(data, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x1E, 2), 9);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x20, 2), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x30, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x38, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x3C, 4), end);
        for (var index = 0; index < 109; index++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x4C + index * 4, 4), free);
        }
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x4C, 4), 0);

        var fat = data.AsSpan(512, 512);
        for (var offset = 0; offset < fat.Length; offset += 4)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(offset, 4), free);
        }
        BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(0, 4), 0xFFFFFFFD);
        BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(4, 4), end);
        BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(8, 4), end);
        BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(12, 4), end);

        static void DirectoryEntry(Span<byte> entry, string name, byte type, uint start, ulong size)
        {
            var encoded = Encoding.Unicode.GetBytes(name + "\0");
            encoded.CopyTo(entry);
            BinaryPrimitives.WriteUInt16LittleEndian(entry.Slice(0x40, 2), checked((ushort)encoded.Length));
            entry[0x42] = type;
            BinaryPrimitives.WriteUInt32LittleEndian(entry.Slice(0x74, 4), start);
            BinaryPrimitives.WriteUInt64LittleEndian(entry.Slice(0x78, 8), size);
        }

        var directory = data.AsSpan(1024, 512);
        DirectoryEntry(directory.Slice(0, 128), "Root Entry", 5, end, 0);
        DirectoryEntry(directory.Slice(128, 128), "1", 2, 2, 0x4C);
        DirectoryEntry(directory.Slice(256, 128), "DestList", 2, 3, 162);

        var link = BuildShellLink();
        link.AsSpan(0, 0x4C).CopyTo(data.AsSpan(1536, 0x4C));

        var destList = data.AsSpan(2048, 162);
        BinaryPrimitives.WriteUInt32LittleEndian(destList, 3);
        const int entryOffset = 32;
        BinaryPrimitives.WriteUInt32LittleEndian(destList.Slice(entryOffset + 88, 4), 1);
        BinaryPrimitives.WriteInt64LittleEndian(destList.Slice(entryOffset + 100, 8), timestamp.ToFileTime());
        BinaryPrimitives.WriteUInt16LittleEndian(destList.Slice(entryOffset + 128, 2), 0);
        return data;
    }

    private static byte[] BuildShimcacheEntry(string path, long? fileTime = null, bool oddPathLength = false)
    {
        var pathBytes = Encoding.Unicode.GetBytes(path);
        var declaredLength = pathBytes.Length + (oddPathLength ? 1 : 0);
        var payloadSize = 2 + declaredLength + (fileTime.HasValue ? 8 : 0);
        var data = new byte[12 + payloadSize];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 0x73743031);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8, 4), checked((uint)payloadSize));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12, 2), checked((ushort)declaredLength));
        pathBytes.CopyTo(data, 14);
        if (fileTime.HasValue)
        {
            BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(14 + declaredLength, 8), fileTime.Value);
        }
        return data;
    }

    private static string EventXml(string provider, int eventId, params (string Name, string Value)[] fields)
    {
        var data = string.Concat(fields.Select(field =>
            $"<Data Name=\"{SecurityElement.Escape(field.Name)}\">{SecurityElement.Escape(field.Value)}</Data>"));
        return $"""
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                  <System>
                    <Provider Name="{SecurityElement.Escape(provider)}" />
                    <EventID>{eventId}</EventID>
                    <EventRecordID>42</EventRecordID>
                    <TimeCreated SystemTime="2026-01-02T03:04:05Z" />
                    <Channel>System</Channel><Computer>HOST</Computer>
                  </System>
                  <EventData>{data}</EventData>
                </Event>
                """;
    }

    private static int WriteString(byte[] data, int offset, string value, Encoding encoding)
    {
        var bytes = encoding.GetBytes(value + "\0");
        bytes.CopyTo(data, offset);
        return bytes.Length;
    }

    private static void WriteFileTime(byte[] data, int offset, DateTimeOffset? value) =>
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(offset, 8), value?.ToFileTime() ?? 0);

    private static void WriteInt32(byte[] data, int offset, int value) =>
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(offset, 4), value);

    private static DateTimeOffset Utc(int year, int month, int day) =>
        new(year, month, day, 0, 0, 0, TimeSpan.Zero);

    private static void AssertParsedFileTime(DateTimeOffset expected, object value)
    {
        Assert.True(UsbRegistryForensicHelpers.TryParseFileTime(value, out var parsed));
        Assert.Equal(expected, parsed);
    }
}
