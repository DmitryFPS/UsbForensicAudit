using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class MaturityHardeningTests
{
    private static UsbDeviceRecord Device(string id, string serial = "REAL-SERIAL-123", string vid = "0951", string pid = "1666") =>
        new() { DeviceInstanceId = id, Serial = serial, Vid = vid, Pid = pid };

    private static AuditResult Scan(string machine, params UsbDeviceRecord[] devices) =>
        new() { ComputerName = machine, Devices = devices.ToList() };

    [Theory]
    [InlineData("0000000000")]
    [InlineData("1234567890")]
    [InlineData("6&123ABC&0&1")]
    [InlineData("FFFFFFFF")]
    public void Placeholder_and_generated_serials_never_prove_same_instance(string serial)
    {
        var result = FleetAnalyzer.Analyze([Scan("A", Device("a", serial)), Scan("B", Device("b", serial))]);
        Assert.All(result.Devices, x => Assert.False(x.IdentifiedBySerial));
        Assert.DoesNotContain("сильный сигнал", result.Verdict());
    }

    [Fact]
    public void Conflicting_models_do_not_merge_even_with_valid_shared_serial()
    {
        var result = FleetAnalyzer.Analyze([
            Scan("A", Device("a")), Scan("B", Device("b", vid: "04E8", pid: "6860"))]);
        Assert.Equal(2, result.Devices.Count);
        Assert.Empty(result.CrossMachineDevices);
    }

    [Fact]
    public void Missing_model_does_not_bridge_conflicting_devices_between_computers()
    {
        var result = FleetAnalyzer.Analyze([
            Scan("A", Device("a")), Scan("B", Device("b", vid: "04E8", pid: "6860")),
            Scan("C", Device("c", vid: "", pid: "")), Scan("D", Device("d", vid: "", pid: ""))]);
        Assert.Empty(result.CrossMachineDevices);
    }

    [Fact]
    public void Reliable_matching_identifiers_do_not_imply_file_transfer()
    {
        var result = FleetAnalyzer.Analyze([Scan("A", Device("a")), Scan("B", Device("b"))]);
        Assert.True(Assert.Single(result.CrossMachineDevices).IdentifiedBySerial);
        Assert.Contains("не подтверждает перенос файлов", result.Verdict());
    }

    [Theory]
    [InlineData("Low")]
    [InlineData("Medium")]
    [InlineData("Unknown")]
    public void One_ambiguous_observation_is_not_counted_once_per_candidate(string confidence)
    {
        var a = Device("a");
        var b = Device("b");
        var entry = Entry(confidence);
        var summary = FileActivitySummary.From([(a, History(entry)), (b, History(entry))]);
        Assert.Equal(0, summary.DirectCount);
        Assert.Equal(1, summary.UncertainCount);
        Assert.Equal(0, summary.DeviceCount);
        Assert.Contains("Возможная", summary.Verdict);
    }

    [Fact]
    public void Two_strong_but_conflicting_links_are_still_ambiguous()
    {
        var entry = Entry("High");
        var summary = FileActivitySummary.From([(Device("a"), History(entry)), (Device("b"), History(entry))]);
        Assert.Equal(0, summary.DirectCount);
        Assert.Equal(1, summary.UncertainCount);
    }

    [Fact]
    public void A_strong_link_takes_precedence_over_a_drive_letter_candidate()
    {
        var strong = Entry("High");
        var weak = Entry("Low");
        var summary = FileActivitySummary.From([(Device("a"), History(strong)), (Device("b"), History(weak))]);
        Assert.Equal(1, summary.DirectCount);
        Assert.Equal(0, summary.UncertainCount);
        Assert.Equal(1, summary.DeviceCount);
    }

    [Fact]
    public void Independent_records_and_users_are_not_collapsed()
    {
        var first = Entry("High");
        var second = Entry("High");
        second.UserSid = "S-1-5-21-second";
        var summary = FileActivitySummary.From([(Device("a"), History(first, second))]);
        Assert.Equal(2, summary.DirectCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Successful_privilege_description_does_not_make_a_complete_scan_partial(bool system)
    {
        var result = new AuditResult { Privileges = new(true, system, true, true) };
        result.Coverage.Sources.Add(new SourceCoverage { Source = "Fixture", Status = "Complete" });
        result.SourceWarnings.Add(result.Privileges.Describe());
        Assert.False(ScanCoverageSummary.From(result).HasLimitations);
        result.SourceWarnings.Add("Нельзя прочитать защищённый журнал");
        Assert.True(ScanCoverageSummary.From(result).HasLimitations);
    }

    [Theory]
    [InlineData("Error")]
    [InlineData("Partial")]
    [InlineData("NotRun")]
    public void Missing_sources_stay_visible_without_warning_text(string status)
    {
        var result = new AuditResult();
        result.Coverage.Sources.Add(new SourceCoverage { Source = "Fixture", Status = status });
        Assert.True(ScanCoverageSummary.From(result).HasLimitations);
    }

    private static DeviceActivityHistory History(params DeviceActivityEntry[] entries) => new() { Entries = entries.ToList() };

    [Fact]
    public void Manager_report_does_not_show_green_overall_verdict_for_an_unreliable_file_link()
    {
        var device = Device(@"USB\VID_0951&PID_1666\REAL-SERIAL-123");
        device.DriveLetters = "E:";
        device.DeviceKind = DeviceKindResolver.Storage;
        device.VisualCategory = "RealUsb";
        var scan = Scan("A", device);
        scan.Evidence.Add(new EvidenceRecord { Source = "LNK", DeviceHint = @"E:\file.txt" });
        var context = ForensicReportContext.Create(scan);
        Assert.Equal("требуется проверка", ManagerOnePagePdfReport.OverallRisk(context).Label);
    }

    [Fact]
    public void Activity_limit_is_visible_in_dossier_and_summary_even_when_file_actions_are_outside_the_slice()
    {
        var device = new UsbDeviceRecord { DriveLetters = "E:" };
        var evidence = Enumerable.Range(0, DeviceActivityBuilder.MaxEntries + 1)
            .Select(i => new EvidenceRecord { Source = "LNK", DeviceHint = $@"E:\file-{i}.txt" }).ToArray();
        var history = DeviceActivityBuilder.Build(device, [device], evidence);
        Assert.Equal(DeviceActivityBuilder.MaxEntries, history.Entries.Count);
        Assert.Equal(1, history.OmittedEntryCount);
        Assert.Contains("ещё 1 записей не показано", history.Verdict());
        Assert.Equal(1, history.FileActionsOnly().OmittedEntryCount);
        history.Entries.Clear();
        var summary = FileActivitySummary.From([(device, history.FileActionsOnly())]);
        Assert.Contains("история ограничена", summary.Verdict);
        Assert.Contains("показанной части", summary.Explanation);
    }

    [Fact]
    public void Records_without_ids_do_not_reuse_another_devices_cached_activity()
    {
        var first = new UsbDeviceRecord { DriveLetters = "E:" };
        var second = new UsbDeviceRecord { DriveLetters = "F:" };
        var scan = Scan("A", first, second);
        scan.Evidence.Add(new EvidenceRecord { Source = "LNK", DeviceHint = @"E:\first.txt" });
        scan.Evidence.Add(new EvidenceRecord { Source = "LNK", DeviceHint = @"F:\second.txt" });
        var context = ForensicReportContext.Create(scan);
        Assert.Equal(@"E:\first.txt", Assert.Single(context.GetActivity(first).Entries).Path);
        Assert.Equal(@"F:\second.txt", Assert.Single(context.GetActivity(second).Entries).Path);
    }

    [Fact]
    public void Activity_builder_preserves_distinct_users_at_the_same_path_and_time()
    {
        var device = Device(@"USB\VID_0951&PID_1666\REAL-SERIAL-123");
        device.Volumes.Add(new VolumeIdentity { DriveLetter = "E:" });
        var when = DateTimeOffset.Parse("2026-09-01T12:00:00Z");
        var entries = new[] { "S-1-5-21-A", "S-1-5-21-B" }.Select(sid => new EvidenceRecord
        { Source = "LNK", DeviceHint = @"E:\report.txt", TimestampUtc = when, UserSid = sid }).ToArray();
        var history = DeviceActivityBuilder.Build(device, [device], entries);
        Assert.Equal(2, history.Entries.Count);
        Assert.Contains("косвенная или неоднозначная", history.Verdict());
    }

    private static DeviceActivityEntry Entry(string confidence) => new()
    {
        TimestampUtc = DateTimeOffset.Parse("2026-09-01T12:00:00Z"),
        Kind = DeviceActivityKind.FileOpen,
        Path = @"E:\report.txt",
        Source = "LNK",
        Provenance = "fixture.lnk",
        LinkConfidence = confidence
    };
}
