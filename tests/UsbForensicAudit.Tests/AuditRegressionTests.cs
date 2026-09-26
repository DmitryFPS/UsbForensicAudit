using System.IO;
using System.IO.Compression;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class AuditRegressionTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "ufa-regression-" + Guid.NewGuid().ToString("N"));

    public AuditRegressionTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        Directory.Delete(_directory, recursive: true);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(0)]
    public void Integrity_detects_truncated_sealed_session(int retainedLines)
    {
        var storage = new AuditStorage(_directory);
        storage.Save(new AuditResult { Devices = [new UsbDeviceRecord { DeviceInstanceId = "test-device" }] });
        var lines = File.ReadAllLines(storage.JsonlPath);
        File.WriteAllLines(storage.JsonlPath, lines.Take(retainedLines));

        var report = new EvidenceIntegrityVerifier(storage).Verify();

        Assert.False(report.IsIntact);
        Assert.Equal(SealStatus.Mismatch, Assert.Single(report.SealChecks).Status);
    }

    [Fact]
    public void Integrity_detects_removal_of_entire_last_session()
    {
        var storage = new AuditStorage(_directory);
        storage.Save(new AuditResult());
        var original = File.ReadAllText(storage.JsonlPath);
        var second = new AuditResult();
        storage.Save(second);
        File.WriteAllText(storage.JsonlPath, original);

        var report = new EvidenceIntegrityVerifier(storage).Verify();

        Assert.False(report.IsIntact);
        Assert.Contains(report.SealChecks, x => x.SessionId == second.SessionId && x.Status == SealStatus.Mismatch);
    }

    [Fact]
    public void Integrity_detects_deleted_journal_when_database_contains_sessions()
    {
        var storage = new AuditStorage(_directory);
        storage.Save(new AuditResult());
        File.Delete(storage.JsonlPath);

        var report = new EvidenceIntegrityVerifier(storage).Verify();

        Assert.True(report.JournalMissing);
        Assert.False(report.IsIntact);
        Assert.Equal(SealStatus.Mismatch, Assert.Single(report.SealChecks).Status);
    }

    [Fact]
    public void Legacy_session_without_new_metadata_columns_still_loads()
    {
        var storage = new AuditStorage(_directory);
        var result = new AuditResult { IsAdministrator = true };
        storage.Save(result);
        using (var connection = new SqliteConnection($"Data Source={storage.DatabasePath};Pooling=False"))
        {
            connection.Open();
            foreach (var column in new[] { "privileges_json", "reference_image_json", "file_change_journals_json" })
            {
                using var command = connection.CreateCommand();
                command.CommandText = $"ALTER TABLE audit_sessions DROP COLUMN {column};";
                command.ExecuteNonQuery();
            }
        }

        var reopened = new AuditStorage(_directory);
        var loaded = Assert.IsType<AuditResult>(reopened.Load(result.SessionId));

        Assert.True(loaded.Privileges.IsAdministrator);
        Assert.Empty(loaded.ReferenceImage.Signals);
        Assert.Empty(loaded.FileChangeJournals);
        Assert.True(new EvidenceIntegrityVerifier(reopened).Verify().IsIntact);
    }

    [Fact]
    public void Network_merging_preserves_simultaneous_sessions_of_different_accounts()
    {
        var time = DateTimeOffset.UtcNow;
        var connection = new NetworkConnectionRecord
        {
            Kind = NetworkConnectionKind.RemoteDesktop,
            Name = "server",
            Sessions =
            [
                new() { StartedUtc = time, Account = "DOMAIN\\Alice" },
                new() { StartedUtc = time, Account = "DOMAIN\\Bob" }
            ]
        };

        var merged = Assert.Single(NetworkConnectionMerger.Merge([connection]));

        Assert.Equal(2, merged.Sessions.Count);
    }

    [Fact]
    public void Network_time_provenance_changes_when_time_is_replaced_by_session()
    {
        var time = DateTimeOffset.UtcNow;
        var connection = new NetworkConnectionRecord
        {
            Kind = NetworkConnectionKind.WiFi,
            Name = "network",
            FirstSeenUtc = time,
            LastSeenUtc = time,
            FirstSeenProvenance = "Дата создания профиля",
            LastSeenProvenance = "Дата изменения профиля",
            Sessions = [new() { StartedUtc = time.AddDays(-2), EndedUtc = time.AddDays(2), Provenance = "Журнал WLAN" }]
        };

        var merged = Assert.Single(NetworkConnectionMerger.Merge([connection]));

        Assert.Equal(time.AddDays(-2), merged.FirstSeenUtc);
        Assert.DoesNotContain("профиля", merged.FirstSeenProvenance);
        Assert.Contains("Журнал WLAN", merged.FirstSeenProvenance);
        Assert.Equal(time.AddDays(2), merged.LastSeenUtc);
        Assert.DoesNotContain("профиля", merged.LastSeenProvenance);
        Assert.Contains("Журнал WLAN", merged.LastSeenProvenance);
    }

    [Theory]
    [InlineData("7&2A1B3C4D&0")]
    [InlineData("3&11583659&0&6A")]
    [InlineData("0000000000000000")]
    [InlineData("0123456789ABCDEF")]
    public void Generated_and_placeholder_serials_are_not_strong_identity(string serial)
    {
        Assert.False(DeviceIdentityGraph.IsHardwareSerial(serial));
    }

    [Fact]
    public void Session_comparison_recognizes_same_instance_after_canonical_key_upgrade()
    {
        var baseline = new AuditResult
        {
            Devices = [new() { CanonicalDeviceId = "DEV-OLD", DeviceInstanceId = @"USB\VID_1111&PID_2222\ABC12345" }]
        };
        var target = new AuditResult
        {
            Devices = [new() { CanonicalDeviceId = "DEV-NEW", DeviceInstanceId = @"usb\vid_1111&pid_2222\abc12345" }]
        };

        Assert.False(SessionDiffService.Compare(baseline, target).HasChanges);
    }

    [Fact]
    public void Offline_report_does_not_hash_matching_path_on_analyst_machine()
    {
        var path = Path.Combine(_directory, "evidence-program.exe");
        File.WriteAllText(path, "файл на машине аналитика");
        var result = new AuditResult
        {
            SessionId = "offline-test",
            Devices = [new() { DeviceInstanceId = @"USBSTOR\Disk&Ven_Test\ABC12345", DriveLetters = Path.GetPathRoot(path)!, DeviceKind = DeviceKindResolver.Storage }],
            Evidence = [new() { Source = "Prefetch", DeviceHint = path }]
        };
        DeviceTransportClassifier.ClassifyAll(result.Devices);

        var context = ForensicReportContext.Create(result, policy: DevicePolicy.None, caseMetadata: new CaseMetadata());

        var hash = Assert.Single(context.UsbExecutableHashes);
        Assert.NotEqual(FileHashStatus.Hashed, hash.Status);
        Assert.Null(hash.Sha256);
        Assert.Contains("Офлайн", hash.Error);
    }

    [Fact]
    public void Saved_session_preserves_forensic_context_and_journal_metadata()
    {
        var result = new AuditResult
        {
            IsAdministrator = true,
            Privileges = new PrivilegeState(true, false, true, false),
            ReferenceImage = new ReferenceImageTrace { PreparedAtUtc = DateTimeOffset.UtcNow.AddDays(-5) },
            FileChangeJournals = [new FileChangeJournalState { Volume = "C:", Available = true, RecordsRead = 12 }]
        };
        result.ReferenceImage.Add("Образ", "Подтверждение", isDecisive: true);
        var storage = new AuditStorage(_directory);
        storage.Save(result);

        var loaded = Assert.IsType<AuditResult>(storage.Load(result.SessionId));

        Assert.Equal(result.Privileges, loaded.Privileges);
        Assert.Equal(result.ReferenceImage.PreparedAtUtc, loaded.ReferenceImage.PreparedAtUtc);
        Assert.True(loaded.ReferenceImage.WasDeployedFromImage);
        Assert.Equal("Подтверждение", Assert.Single(loaded.ReferenceImage.Signals).Detail);
        Assert.Equal(12, Assert.Single(loaded.FileChangeJournals).RecordsRead);
        Assert.True(ExfiltrationAnalyzer.Analyze(loaded).JournalAvailable);

        using var record = JsonDocument.Parse(File.ReadLines(storage.JsonlPath).First());
        var data = record.RootElement.GetProperty("data");
        Assert.True(data.GetProperty("Privileges").GetProperty("BackupPrivilegeEnabled").GetBoolean());
        Assert.Single(data.GetProperty("ReferenceImage").GetProperty("Signals").EnumerateArray());
        Assert.Single(data.GetProperty("FileChangeJournals").EnumerateArray());
    }

    [Theory]
    [InlineData("1234", "1666")]
    [InlineData("0951", "9999")]
    [InlineData("1234", "9999")]
    public void Unknown_device_with_same_serial_but_different_model_is_reported(string vid, string pid)
    {
        var detector = new UnknownDeviceDetector([new KnownDeviceIdentity("0951", "1666", "ABC12345", "")]);
        var live = new LiveUsbDevice { DeviceId = $@"USB\VID_{vid}&PID_{pid}\ABC12345", Vid = vid, Pid = pid };

        Assert.Single(detector.DetectNew([live]));
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("ABC12345", "XYZ67890")]
    public void Different_scsi_disks_of_same_model_are_not_merged(string firstSerial, string secondSerial)
    {
        var first = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SCSI\Disk&Ven_Test&Prod_External_Disk\7&123&0&000000",
            FriendlyName = "External Disk",
            Serial = firstSerial
        };
        var second = new UsbDeviceRecord
        {
            DeviceInstanceId = @"SCSI\Disk&Ven_Test&Prod_External_Disk\7&456&0&000000",
            FriendlyName = "External Disk",
            Serial = secondSerial
        };

        Assert.False(DeviceLiveMatcher.AreLikelySameDevice(first, second));
        Assert.Null(LiveDeviceMerger.FindMatch([first], second));
    }

    [Fact]
    public void Empty_container_guid_does_not_merge_unrelated_devices()
    {
        var first = new UsbDeviceRecord { DeviceInstanceId = @"USB\FIRST", ContainerId = Guid.Empty.ToString("B") };
        var second = new UsbDeviceRecord { DeviceInstanceId = @"USB\SECOND", ContainerId = Guid.Empty.ToString("B") };

        Assert.False(DeviceLiveMatcher.AreLikelySameDevice(first, second));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Identity_graph_does_not_join_different_models_through_shared_serial(bool reverse)
    {
        var devices = new List<UsbDeviceRecord>
        {
            new() { DeviceInstanceId = @"USB\VID_1111&PID_2222\ABC12345", Vid = "1111", Pid = "2222", Serial = "ABC12345" },
            new() { DeviceInstanceId = @"USB\VID_3333&PID_4444\ABC12345", Vid = "3333", Pid = "4444", Serial = "ABC12345" },
            new() { DeviceInstanceId = @"USBSTOR\Disk&Ven_Unknown\ABC12345", Serial = "ABC12345" }
        };
        if (reverse)
        {
            devices.Reverse();
        }

        DeviceIdentityGraph.Process(devices);

        Assert.Equal(3, devices.Select(x => x.CanonicalDeviceId).Distinct().Count());
        Assert.All(devices, x => Assert.True(x.IsCanonicalPrimary));
    }

    [Fact]
    public void Identity_graph_does_not_merge_two_serialized_devices_used_in_same_port()
    {
        var devices = new List<UsbDeviceRecord>
        {
            new() { DeviceInstanceId = @"USB\VID_1111&PID_2222\ABC12345", Vid = "1111", Pid = "2222", Serial = "ABC12345", LocationPaths = "PCIROOT(0)#USBROOT(0)#USB(1)" },
            new() { DeviceInstanceId = @"USB\VID_1111&PID_2222\XYZ67890", Vid = "1111", Pid = "2222", Serial = "XYZ67890", LocationPaths = "PCIROOT(0)#USBROOT(0)#USB(1)" }
        };

        DeviceIdentityGraph.Process(devices);

        Assert.NotEqual(devices[0].CanonicalDeviceId, devices[1].CanonicalDeviceId);
    }

    [Fact]
    public async Task Network_capture_stays_attached_to_session_that_started_it()
    {
        var storage = new AuditStorage(_directory);
        var first = new AuditResult();
        var second = new AuditResult();
        storage.Save(first);
        storage.Save(second);
        var service = new DeferredNetworkService();
        var orchestrator = new AuditOrchestrator(null!, [], null!, null!, null!, null!, null!, storage, null!);
        var vm = new MainViewModel(orchestrator, null!, service, null!) { LastResult = first };

        var capture = vm.CaptureNetworkEnvironmentAsync(false);
        await service.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        vm.LastResult = second;
        var snapshot = new NetworkEnvironmentSnapshot { TakenAtUtc = DateTimeOffset.UtcNow };
        service.Completion.SetResult(snapshot);
        await capture;

        Assert.Same(snapshot, first.NetworkEnvironment);
        Assert.Null(second.NetworkEnvironment.TakenAtUtc);
        Assert.Equal(snapshot.TakenAtUtc, storage.Load(first.SessionId)!.NetworkEnvironment.TakenAtUtc);
        Assert.Null(storage.Load(second.SessionId)!.NetworkEnvironment.TakenAtUtc);
        Assert.Contains("не снималась", vm.NetworkEnvironmentSummary);
        Assert.False(vm.IsCapturingNetworkEnvironment);
    }

    private sealed class DeferredNetworkService : INetworkEnvironmentService
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<NetworkEnvironmentSnapshot> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<NetworkEnvironmentSnapshot> CaptureAsync(bool activeProbe, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        {
            Started.SetResult();
            return Completion.Task;
        }
    }

    [Fact]
    public void Failed_journal_reads_do_not_claim_that_journal_was_available()
    {
        var result = new AuditResult
        {
            FileChangeJournals = [new FileChangeJournalState { Volume = "C:", Available = false, Note = "Нет доступа" }]
        };

        Assert.False(ExfiltrationAnalyzer.Analyze(result).JournalAvailable);
    }

    [Fact]
    public void Package_reserves_manifest_name_for_generated_manifest()
    {
        var input = Path.Combine(_directory, "manifest.json");
        File.WriteAllText(input, "исходное доказательство");
        var output = Path.Combine(_directory, "package.zip");

        EvidencePackageBuilder.Build(output, [input]);

        using var zip = ZipFile.OpenRead(output);
        Assert.Equal(zip.Entries.Count, zip.Entries.Select(x => x.FullName).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        using var manifestStream = zip.GetEntry("manifest.json")!.Open();
        using var manifest = JsonDocument.Parse(manifestStream);
        var file = Assert.Single(manifest.RootElement.GetProperty("Files").EnumerateArray());
        using var reader = new StreamReader(zip.GetEntry(file.GetProperty("File").GetString()!)!.Open());
        Assert.Equal("исходное доказательство", reader.ReadToEnd());
    }

    [Fact]
    public void Package_accepts_artifact_timestamp_before_zip_epoch()
    {
        var input = Path.Combine(_directory, "old-evidence.txt");
        File.WriteAllText(input, "артефакт");
        File.SetLastWriteTime(input, new DateTime(1970, 1, 1));
        var output = Path.Combine(_directory, "package.zip");

        EvidencePackageBuilder.Build(output, [input]);

        using var zip = ZipFile.OpenRead(output);
        Assert.Equal(1980, zip.GetEntry("old-evidence.txt")!.LastWriteTime.Year);
    }
}
