using System.IO;
using Microsoft.Data.Sqlite;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class SessionDiffServiceTests
{
    [Fact]
    public void Compare_detects_added_and_removed_devices_by_canonical_id()
    {
        var baseline = CreateResult("session-old", "2026-01-01T10:00:00Z");
        baseline.Devices.Add(Device("canonical-kingston", "SERIAL-A", "Kingston DataTraveler"));
        baseline.Devices.Add(Device("canonical-old", "SERIAL-OLD", "Old Drive"));

        var target = CreateResult("session-new", "2026-02-01T10:00:00Z");
        target.Devices.Add(Device("canonical-kingston", "SERIAL-A", "Kingston DataTraveler"));
        target.Devices.Add(Device("canonical-new", "SERIAL-NEW", "New Drive"));

        var diff = SessionDiffService.Compare(baseline, target);

        Assert.True(diff.HasChanges);
        Assert.Single(diff.AddedDevices);
        Assert.Equal("New Drive", diff.AddedDevices[0].FriendlyName);
        Assert.Single(diff.RemovedDevices);
        Assert.Equal("Old Drive", diff.RemovedDevices[0].FriendlyName);
    }

    [Fact]
    public void Compare_matches_devices_without_canonical_id_by_source_and_instance()
    {
        var baseline = CreateResult("session-old", "2026-01-01T10:00:00Z");
        baseline.Devices.Add(Device("", @"USB\VID_0951&PID_1666\SERIAL-A", "Drive"));

        var target = CreateResult("session-new", "2026-02-01T10:00:00Z");
        target.Devices.Add(Device("", @"USB\VID_0951&PID_1666\SERIAL-A", "Drive"));

        var diff = SessionDiffService.Compare(baseline, target);

        Assert.Empty(diff.AddedDevices);
        Assert.Empty(diff.RemovedDevices);
        Assert.False(diff.HasChanges);
    }

    [Fact]
    public void Compare_reports_missing_evidence_as_forensic_signal()
    {
        var baseline = CreateResult("session-old", "2026-01-01T10:00:00Z");
        baseline.Evidence.Add(Evidence("EventLog: System", "2100", "USB device started"));
        baseline.Evidence.Add(Evidence("Registry: USBSTOR", "", "Registry key present"));

        var target = CreateResult("session-new", "2026-02-01T10:00:00Z");
        target.Evidence.Add(Evidence("Registry: USBSTOR", "", "Registry key present"));

        var diff = SessionDiffService.Compare(baseline, target);

        Assert.Single(diff.MissingEvidence);
        Assert.Equal("EventLog: System", diff.MissingEvidence[0].Source);
        Assert.Empty(diff.AddedEvidence);
    }

    [Fact]
    public void Compare_reports_only_new_cleanup_findings()
    {
        var baseline = CreateResult("session-old", "2026-01-01T10:00:00Z");
        baseline.CleanupFindings.Add(Cleanup("EventLog", "Журнал очищен"));

        var target = CreateResult("session-new", "2026-02-01T10:00:00Z");
        target.CleanupFindings.Add(Cleanup("EventLog", "Журнал очищен"));
        target.CleanupFindings.Add(Cleanup("Registry", "Ветка USBSTOR удалена"));

        var diff = SessionDiffService.Compare(baseline, target);

        Assert.Single(diff.AddedCleanupFindings);
        Assert.Equal("Registry", diff.AddedCleanupFindings[0].Area);
    }

    [Fact]
    public void Compare_detects_network_connection_changes_by_canonical_key()
    {
        var baseline = CreateResult("session-old", "2026-01-01T10:00:00Z");
        baseline.NetworkConnections.Add(Network("wifi|HomeNet", "HomeNet"));

        var target = CreateResult("session-new", "2026-02-01T10:00:00Z");
        target.NetworkConnections.Add(Network("wifi|OfficeNet", "OfficeNet"));

        var diff = SessionDiffService.Compare(baseline, target);

        Assert.Single(diff.AddedNetworkConnections);
        Assert.Equal("OfficeNet", diff.AddedNetworkConnections[0].Name);
        Assert.Single(diff.RemovedNetworkConnections);
        Assert.Equal("HomeNet", diff.RemovedNetworkConnections[0].Name);
    }

    [Fact]
    public void Compare_fills_summaries_for_both_sessions()
    {
        var baseline = CreateResult("session-old", "2026-01-01T10:00:00Z");
        baseline.Devices.Add(Device("canonical-a", "SERIAL-A", "Drive A"));
        var target = CreateResult("session-new", "2026-02-01T10:00:00Z");

        var diff = SessionDiffService.Compare(baseline, target);

        Assert.Equal("session-old", diff.Baseline.SessionId);
        Assert.Equal(1, diff.Baseline.DeviceCount);
        Assert.Equal("session-new", diff.Target.SessionId);
        Assert.Equal(0, diff.Target.DeviceCount);
        Assert.Equal("PC-01", diff.Baseline.ComputerName);
    }

    [Fact]
    public void Identical_sessions_have_no_changes()
    {
        var baseline = CreateResult("session-old", "2026-01-01T10:00:00Z");
        baseline.Devices.Add(Device("canonical-a", "SERIAL-A", "Drive A"));
        baseline.Evidence.Add(Evidence("EventLog: System", "2100", "USB device started"));

        var target = CreateResult("session-new", "2026-02-01T10:00:00Z");
        target.Devices.Add(Device("canonical-a", "SERIAL-A", "Drive A"));
        target.Evidence.Add(Evidence("EventLog: System", "2100", "USB device started"));

        var diff = SessionDiffService.Compare(baseline, target);

        Assert.False(diff.HasChanges);
    }

    [Fact]
    public void Storage_lists_saved_sessions_newest_first_with_counts()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-diff-{Guid.NewGuid():N}");
        try
        {
            var storage = new AuditStorage(directory);

            var older = CreateResult("session-older", "2026-01-01T10:00:00Z");
            older.Devices.Add(Device("canonical-a", "SERIAL-A", "Drive A"));
            older.Evidence.Add(Evidence("EventLog: System", "2100", "USB device started"));
            storage.Save(older);

            var newer = CreateResult("session-newer", "2026-02-01T10:00:00Z");
            newer.Devices.Add(Device("canonical-a", "SERIAL-A", "Drive A"));
            newer.Devices.Add(Device("canonical-b", "SERIAL-B", "Drive B"));
            storage.Save(newer);

            var sessions = storage.ListSessions();

            Assert.Equal(2, sessions.Count);
            Assert.Equal("session-newer", sessions[0].SessionId);
            Assert.Equal(2, sessions[0].DeviceCount);
            Assert.Equal("session-older", sessions[1].SessionId);
            Assert.Equal(1, sessions[1].DeviceCount);
            Assert.Equal(1, sessions[1].EvidenceCount);
            Assert.Equal("PC-01", sessions[0].ComputerName);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, true);
            }
        }
    }

    [Fact]
    public void Storage_diff_round_trip_detects_new_device_between_saved_sessions()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-diff-rt-{Guid.NewGuid():N}");
        try
        {
            var storage = new AuditStorage(directory);

            var baseline = CreateResult("session-baseline", "2026-01-01T10:00:00Z");
            baseline.Devices.Add(Device("canonical-a", "SERIAL-A", "Drive A"));
            storage.Save(baseline);

            var target = CreateResult("session-target", "2026-02-01T10:00:00Z");
            target.Devices.Add(Device("canonical-a", "SERIAL-A", "Drive A"));
            target.Devices.Add(Device("canonical-b", "SERIAL-B", "Drive B"));
            storage.Save(target);

            var loadedBaseline = storage.Load("session-baseline");
            var loadedTarget = storage.Load("session-target");
            Assert.NotNull(loadedBaseline);
            Assert.NotNull(loadedTarget);

            var diff = SessionDiffService.Compare(loadedBaseline, loadedTarget);

            Assert.Single(diff.AddedDevices);
            Assert.Equal("Drive B", diff.AddedDevices[0].FriendlyName);
            Assert.Empty(diff.RemovedDevices);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, true);
            }
        }
    }

    private static AuditResult CreateResult(string sessionId, string startedAt)
    {
        var started = DateTimeOffset.Parse(startedAt);
        return new AuditResult
        {
            SessionId = sessionId,
            StartedAtUtc = started,
            FinishedAtUtc = started.AddMinutes(3),
            ComputerName = "PC-01",
            UserName = "analyst",
            WindowsVersion = "Windows 11 Pro"
        };
    }

    private static UsbDeviceRecord Device(string canonicalId, string serialOrInstance, string friendlyName) =>
        new()
        {
            CanonicalDeviceId = canonicalId,
            DeviceInstanceId = canonicalId.Length > 0
                ? $@"USB\VID_0951&PID_1666\{serialOrInstance}"
                : serialOrInstance,
            Serial = serialOrInstance,
            FriendlyName = friendlyName,
            Source = "Registry: USB",
            VisualCategory = "RealUsb",
            DeviceType = "USB"
        };

    private static EvidenceRecord Evidence(string source, string eventId, string summary) =>
        new()
        {
            TimestampUtc = DateTimeOffset.Parse("2026-01-01T09:00:00Z"),
            Source = source,
            EventId = eventId,
            Summary = summary
        };

    private static CleanupFinding Cleanup(string area, string finding) =>
        new()
        {
            TimestampUtc = DateTimeOffset.Parse("2026-01-01T09:30:00Z"),
            Severity = "High",
            Area = area,
            Finding = finding
        };

    private static NetworkConnectionRecord Network(string canonicalKey, string name) =>
        new()
        {
            CanonicalKey = canonicalKey,
            Kind = "WiFi",
            Name = name
        };
}
