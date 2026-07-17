using System.IO;
using System.Reflection;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class MaturityCoverageTimelineTests
{
    private static readonly DateTimeOffset ScanAt = new(2026, 7, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Timeline_uses_exact_connection_and_latest_disconnect_and_explains_reconnection()
    {
        var device = Device();
        var result = Result(device);
        result.Evidence.AddRange(
        [
            TimelineEvidence(ScanAt.AddDays(-3), "Подключение USB", "Kernel-PnP"),
            TimelineEvidence(ScanAt.AddDays(-2), "Отключение USB", "Kernel-PnP"),
            TimelineEvidence(ScanAt.AddDays(-1), "Отключение USB", "Kernel-PnP")
        ]);

        new TimelineEnricher(new FixedProbe(DeviceId)).Enrich(result);

        Assert.Equal(ScanAt.AddDays(-3), device.FirstConnectedUtc);
        Assert.Equal(ScanAt.AddDays(-1), device.LastDisconnectedUtc);
        Assert.Equal(ScanAt, device.LastSeenUtc);
        Assert.Equal("ExactEvent", device.ConnectionDisplayKind);
        Assert.Equal("ExactEvent", device.DisconnectDisplayKind);
        Assert.Contains("снова подключено", device.DateConfidence, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Timeline_disconnect_only_is_corroborating_activity_but_not_a_connection()
    {
        var device = Device();
        var disconnectedAt = ScanAt.AddHours(-6);
        var result = Result(device);
        result.Evidence.Add(TimelineEvidence(disconnectedAt, "Отключение USB", "Kernel-PnP"));

        new TimelineEnricher().Enrich(result);

        Assert.Null(device.FirstConnectedUtc);
        Assert.Equal(disconnectedAt, device.LastSeenUtc);
        Assert.Equal(disconnectedAt, device.LastDisconnectedUtc);
        Assert.Equal("ExactEvent", device.DisconnectDisplayKind);
        Assert.Contains("системном журнале", device.DateConfidence, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Timeline_connected_device_falls_back_to_registry_activity_when_events_are_unavailable()
    {
        var registryAt = ScanAt.AddDays(-4);
        var device = Device();
        device.RegistryLastWriteUtc = registryAt;
        var result = Result(device);

        new TimelineEnricher(new FixedProbe(DeviceId)).Enrich(result);

        Assert.Equal(registryAt, device.FirstConnectedUtc);
        Assert.Equal(ScanAt, device.LastSeenUtc);
        Assert.Equal("RegistryActivity", device.ConnectionDisplayKind);
        Assert.Equal("ConnectedNow", device.DisconnectDisplayKind);
        Assert.Contains("реестре", device.DateConfidence, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Timeline_connected_device_without_historical_dates_uses_scan_time_fallback()
    {
        var device = Device();
        var result = Result(device);

        new TimelineEnricher(new FixedProbe(DeviceId)).Enrich(result);

        Assert.Equal(ScanAt, device.FirstConnectedUtc);
        Assert.Equal(ScanAt, device.LastSeenUtc);
        Assert.Equal("LiveAtScan", device.ConnectionDisplayKind);
        Assert.Contains("обнаружено при сканировании", device.DateConfidence, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Timeline_preserves_exact_pnp_dates_while_refreshing_live_last_seen()
    {
        var exactAt = ScanAt.AddMonths(-2);
        var disconnectedAt = ScanAt.AddMonths(-1);
        var device = Device();
        device.FirstConnectedUtc = exactAt;
        device.ConnectionDisplayKind = "PnpDevProperty";
        device.LastDisconnectedUtc = disconnectedAt;
        device.DisconnectDisplayKind = "PnpDevProperty";
        var result = Result(device);

        new TimelineEnricher(new FixedProbe(DeviceId)).Enrich(result);

        Assert.Equal(exactAt, device.FirstConnectedUtc);
        Assert.Equal(disconnectedAt, device.LastDisconnectedUtc);
        Assert.Equal(ScanAt, device.LastSeenUtc);
        Assert.Equal("PnpDevProperty", device.ConnectionDisplayKind);
        Assert.Equal("PnpDevProperty", device.DisconnectDisplayKind);
        Assert.Contains("снова подключено", device.DateConfidence, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("Correlation", "", "Корреляция", "Автоматическая связь")]
    [InlineData("Recent LNK", "", "Пользовательская активность", "Ярлык")]
    [InlineData("NTUSER Hive", "", "Пользовательская активность", "реестра профиля")]
    [InlineData("Shimcache", "", "Запуск/исполнение", "Shimcache")]
    [InlineData("setupapi.dev.log", "Отключение USB", "Отключение USB", "удаление")]
    [InlineData("MountPoints2", "", "Сырой системный артефакт", "точку монтирования")]
    [InlineData("Event Log", "", "Очистка/антифорензика", "очистки журналов")]
    [InlineData("Unknown Collector", "", "Сырой системный артефакт", "Системный forensic")]
    public void Timeline_classifies_and_explains_distinct_evidence_sources(
        string source,
        string category,
        string expectedCategory,
        string explanationFragment)
    {
        var evidence = new EvidenceRecord
        {
            Source = source,
            EventId = source == "Event Log" ? "1102" : "",
            EvidenceCategory = category,
            UserExplanation = "\0"
        };
        var result = Result();
        result.Evidence.Add(evidence);

        new TimelineEnricher().Enrich(result);

        Assert.Equal(expectedCategory, evidence.EvidenceCategory);
        Assert.Contains(explanationFragment, evidence.UserExplanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Volume_mappings_merge_aliases_and_attach_by_exact_instance_identifier()
    {
        var device = Device();
        var result = Result(device);
        result.Devices.Add(VolumeMapping(
            new VolumeIdentity
            {
                MappingName = @"\DosDevices\G:",
                DriveLetter = "G:",
                DevicePath = @"\??\USBSTOR#Disk&Ven_Test&Prod_Disk#SERIAL-42&0#{GUID}",
                Source = "Registry: MountedDevices"
            },
            new VolumeIdentity
            {
                MappingName = @"\??\Volume{11111111-2222-3333-4444-555555555555}",
                VolumeGuid = "11111111-2222-3333-4444-555555555555",
                DevicePath = @"\??\USBSTOR#Disk&Ven_Test&Prod_Disk#SERIAL-42&0#{GUID}",
                Source = "Registry: MountedDevices"
            }));

        VolumeCorrelationService.Process(result);

        var volume = Assert.Single(device.Volumes);
        Assert.Equal("G:", volume.DriveLetter);
        Assert.Equal("11111111-2222-3333-4444-555555555555", volume.VolumeGuid);
        Assert.Contains(volume.Provenance, x => x.Contains("alias fingerprint", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(volume.Provenance, x => x.Contains("exact hardware serial", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("G:", device.DriveLetters);
        Assert.Contains("VolumeGuid=", device.VolumeHints);
    }

    [Fact]
    public void Volume_mapping_can_be_confirmed_by_live_wmi_drive_association()
    {
        var device = Device();
        device.Volumes.Add(new VolumeIdentity
        {
            DriveLetter = "H:",
            Source = "Live: WMI associations"
        });
        var result = Result(device);
        result.Devices.Add(VolumeMapping(new VolumeIdentity
        {
            MappingName = @"\DosDevices\H:",
            DriveLetter = "H:",
            DiskSignature = "A1B2C3D4",
            PartitionOffset = 1_048_576,
            Source = "Registry: MountedDevices"
        }));

        VolumeCorrelationService.Process(result);

        Assert.Contains(device.Volumes, x =>
            x.DiskSignature == "A1B2C3D4"
            && x.Provenance.Any(p => p.Contains("Live WMI", StringComparison.OrdinalIgnoreCase)));
        Assert.Contains("DiskSignature=A1B2C3D4", device.VolumeHints);
    }

    [Fact]
    public void Partition_event_links_disk_identifier_and_supplies_normalized_volume_serial()
    {
        var device = Device();
        var result = Result(device);
        result.Devices.Add(VolumeMapping(new VolumeIdentity
        {
            MappingName = @"\??\Volume{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            VolumeGuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
            DiskId = "12345678-1234-1234-1234-123456789ABC",
            Source = "Registry: MountedDevices"
        }));
        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = ScanAt.AddHours(-1),
            Source = "EventLog: Partition/Diagnostic",
            Provider = "Microsoft-Windows-Partition",
            EventId = "1006",
            RecordId = 77,
            DeviceHint = DeviceId,
            RawText =
                $"DiskId=12345678123412341234123456789ABC Device={DeviceId} VolumeSerialNumber=ABCD-1234"
        });

        VolumeCorrelationService.Process(result);

        var volume = Assert.Single(device.Volumes);
        Assert.Equal("ABCD1234", volume.VolumeSerialNumber);
        Assert.Contains(volume.Provenance, x => x.Contains("record 77", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("DiskId=12345678-1234-1234-1234-123456789ABC", device.VolumeHints);
    }

    [Fact]
    public void Partition_event_with_volume_identifier_but_no_exact_device_identifier_is_not_attached()
    {
        var device = Device();
        var result = Result(device);
        result.Devices.Add(VolumeMapping(new VolumeIdentity
        {
            MappingName = @"\??\Volume{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            VolumeGuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
            Source = "Registry: MountedDevices"
        }));
        result.Evidence.Add(new EvidenceRecord
        {
            Source = "Partition/Diagnostic",
            Provider = "Partition",
            EventId = "1006",
            RawText = "Volume={AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}; unrelated device SERIAL-99"
        });

        VolumeCorrelationService.Process(result);

        Assert.Empty(device.Volumes);
    }

    [Fact]
    public void User_artifact_exact_vsn_without_matching_drive_creates_medium_corroboration()
    {
        var device = Device();
        device.CanonicalDeviceId = "USB:SERIAL-42";
        device.Volumes.Add(new VolumeIdentity
        {
            DriveLetter = "G:",
            VolumeSerialNumber = "ABCD1234",
            Source = "Partition event"
        });
        var result = Result(device);
        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = ScanAt.AddMinutes(-10),
            Source = "JumpList Parsed",
            SourceRecord = "entry-1",
            Provenance = "fixture",
            DeviceHint = @"Q:\report.docx",
            RawText = "VSN=ABCD-1234"
        });

        VolumeCorrelationService.Process(result);

        var correlation = Assert.Single(result.Evidence, x => x.Source == "Volume Correlation");
        Assert.Equal("Medium", correlation.Confidence);
        Assert.Equal("Corroborating", correlation.EvidenceStrength);
        Assert.False(correlation.CanEstablishConnectionDate);
        Assert.Contains("точном серийном номере тома", correlation.UserExplanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Cleanup_event_log_clear_parses_initiator_and_correlates_cleaner()
    {
        var clearedAt = ScanAt.AddHours(-2);
        var result = CleanupResult(
            new EvidenceRecord
            {
                TimestampUtc = clearedAt,
                Source = "Security",
                EventId = "1102",
                Summary = "Audit log cleared",
                RawText =
                    "<Event><EventData><Data Name=\"SubjectUserName\">admin</Data><Data Name=\"SubjectDomainName\">LAB</Data><Data Name=\"SubjectUserSid\">S-1-5-21-500</Data></EventData></Event>"
            },
            new EvidenceRecord
            {
                TimestampUtc = clearedAt.AddMinutes(-2),
                Source = "Prefetch",
                EventId = "CLEANER_EXECUTION",
                Summary = "CCLEANER.EXE"
            });

        var findings = new CleanupDetector().Analyze(result);

        var clearing = Assert.Single(findings, x => x.Area == "Event Logs");
        Assert.Equal("LogClearing", clearing.ActionKind);
        Assert.Equal("Administrator", clearing.InitiatorKind);
        Assert.Equal(@"LAB\admin", clearing.InitiatorAccount);
        Assert.Equal("CCleaner", clearing.PossibleTool);
        Assert.Equal("Probable", clearing.Confidence);
    }

    [Fact]
    public void Cleaner_presence_is_deduplicated_and_suppressed_when_execution_exists()
    {
        var result = CleanupResult(
            CleanerEvidence("INVENTORY_PRESENCE", "Amcache", "CCleaner.exe", ScanAt.AddDays(-2)),
            CleanerEvidence("PATH_PRESENT", "Shimcache", "CCleaner.exe", ScanAt.AddDays(-1)),
            CleanerEvidence("INVENTORY_PRESENCE", "Amcache", "USBDeview.exe", ScanAt.AddDays(-2)),
            CleanerEvidence("CLEANER_EXECUTION", "Prefetch", "USBDeview.exe", ScanAt.AddHours(-2)));

        var findings = new CleanupDetector().Analyze(result);

        var presence = Assert.Single(findings, x => x.ActionKind == "ToolPresence");
        Assert.Equal("CCleaner", presence.PossibleTool);
        Assert.Contains("не доказывает запуск", presence.Details, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(findings, x => x.ActionKind == "ToolPresence" && x.PossibleTool == "USBDeview");
    }

    [Fact]
    public void Cleaner_execution_sources_within_five_minutes_merge_into_one_confirmed_finding()
    {
        var result = CleanupResult(
            CleanerEvidence("BAM_EXECUTION", "BAM Parsed", "CCleaner.exe", ScanAt.AddMinutes(-2)),
            CleanerEvidence("CLEANER_EXECUTION", "Prefetch", "CCleaner.exe", ScanAt));

        var findings = new CleanupDetector().Analyze(result);

        var launch = Assert.Single(findings, x => x.PossibleTool == "CCleaner" && x.Area == "Cleaner Artifacts");
        Assert.Equal("Confirmed", launch.Confidence);
        Assert.Contains("Дополнительное подтверждение", launch.Details, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(findings, x => x.ActionKind == "ExecutionGap" && x.PossibleTool == "CCleaner");
    }

    [Fact]
    public void Corroborating_execution_without_prefetch_reports_the_execution_gap_in_details()
    {
        var result = CleanupResult(CleanerEvidence(
            "BAM_EXECUTION",
            "BAM Parsed",
            "BleachBit.exe",
            ScanAt.AddHours(-1)));

        var findings = new CleanupDetector().Analyze(result);

        var finding = Assert.Single(findings, x => x.PossibleTool == "BleachBit" && x.Area == "Cleaner Artifacts");
        Assert.Equal("ToolLaunch", finding.ActionKind);
        Assert.Equal("Probable", finding.Confidence);
        Assert.Contains("Prefetch не найден", finding.Details, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false, "Medium", "Suspicious", "Correlation")]
    [InlineData(true, "Info", "Informational", "NormalMigrationContext")]
    public void Cleanup_contradiction_respects_normal_migration_context(
        bool migrationContext,
        string severity,
        string assessment,
        string actionKind)
    {
        var result = CleanupResult();
        result.Devices.Add(new UsbDeviceRecord
        {
            Source = "Registry: USBSTOR",
            VisualCategory = "RealUsb",
            DeviceType = "USB",
            DeviceInstanceId = DeviceId
        });
        if (migrationContext)
        {
            result.Evidence.Add(new EvidenceRecord { Source = "Windows.old offline hive" });
        }

        var findings = new CleanupDetector().Analyze(result);

        var contradiction = Assert.Single(findings, x =>
            x.Finding.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(severity, contradiction.Severity);
        Assert.Equal(assessment, contradiction.Assessment);
        Assert.Equal(actionKind, contradiction.ActionKind);
    }

    [Fact]
    public void Event_log_clearing_inside_os_install_grace_is_normal_system_activity()
    {
        var installedAt = ScanAt.AddDays(-10);
        var result = CleanupResult(new EvidenceRecord
        {
            TimestampUtc = installedAt.AddHours(2),
            Source = "Security",
            EventId = "1102",
            Summary = "Audit log initialized/cleared during setup"
        });
        result.OsInstalledAtUtc = installedAt;

        var findings = new CleanupDetector().Analyze(result);

        var finding = Assert.Single(findings, x => x.Area == "Event Logs");
        Assert.Equal("OsInstall", finding.Assessment);
        Assert.Equal("OsInstall", finding.ActionKind);
        Assert.Equal("Info", finding.Severity);
        Assert.Equal("SYSTEM (Windows Setup)", finding.InitiatorAccount);
        Assert.Contains($"{OsInstallInfo.PostInstallGraceHours} ч.", finding.Details);
    }

    [Fact]
    public void Setupapi_missing_truncated_and_old_boundaries_are_modeled_without_system_files()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-setupapi-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var missing = Path.Combine(directory, "setupapi.dev.log");
            Assert.False(File.Exists(missing));

            File.WriteAllText(missing, "truncated fixture");
            var info = new FileInfo(missing);
            Assert.True(info.Length < 32 * 1024);

            var installedAt = ScanAt.AddDays(-30);
            var oldCreation = installedAt.AddDays(10);
            Assert.False(InvokeIsFromInitialWindowsSetup(oldCreation.UtcDateTime, installedAt));
            Assert.True(oldCreation > installedAt.Add(OsInstallInfo.PostInstallGracePeriod));
            Assert.True(InvokeIsFromInitialWindowsSetup(installedAt.AddHours(2).UtcDateTime, installedAt));
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    private const string DeviceId = @"USBSTOR\Disk&Ven_Test&Prod_Disk&Rev_1.00\SERIAL-42&0";

    private static AuditResult Result(params UsbDeviceRecord[] devices) => new()
    {
        StartedAtUtc = ScanAt,
        Devices = devices.ToList()
    };

    private static AuditResult CleanupResult(params EvidenceRecord[] evidence) => new()
    {
        StartedAtUtc = ScanAt,
        OsInstalledAtUtc = ScanAt.AddYears(-2),
        Evidence = evidence.ToList()
    };

    private static UsbDeviceRecord Device() => new()
    {
        Source = "Registry: USBSTOR",
        VisualCategory = "RealUsb",
        DeviceType = "USB",
        DeviceInstanceId = DeviceId,
        Serial = "SERIAL-42",
        FriendlyName = "Test USB disk"
    };

    private static UsbDeviceRecord VolumeMapping(params VolumeIdentity[] volumes) => new()
    {
        Source = "Registry: MountedDevices",
        VisualCategory = "SupportArtifact",
        DeviceType = "VolumeMapping",
        DeviceInstanceId = "HKLM\\SYSTEM\\MountedDevices",
        Volumes = volumes.ToList()
    };

    private static EvidenceRecord TimelineEvidence(
        DateTimeOffset timestamp,
        string category,
        string source) => new()
    {
        TimestampUtc = timestamp,
        Source = source,
        EvidenceCategory = category,
        DeviceHint = DeviceId,
        RawText = DeviceId,
        CanEstablishConnectionDate = true
    };

    private static EvidenceRecord CleanerEvidence(
        string eventId,
        string source,
        string executable,
        DateTimeOffset timestamp) => new()
    {
        TimestampUtc = timestamp,
        Source = source,
        EventId = eventId,
        Summary = executable,
        DeviceHint = $@"C:\Tools\{executable}",
        ResolvedUserName = @"LAB\analyst"
    };

    private static bool InvokeIsFromInitialWindowsSetup(DateTime creationTimeUtc, DateTimeOffset installedAt)
    {
        var method = typeof(CleanupDetector).GetMethod(
            "IsFromInitialWindowsSetup",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        return Assert.IsType<bool>(method.Invoke(null, [creationTimeUtc, installedAt]));
    }

    private sealed class FixedProbe(params string[] identifiers) : IConnectedDeviceProbe
    {
        public ConnectedDeviceIndex Capture() => ConnectedDeviceIndex.Build(identifiers, []);
    }
}
