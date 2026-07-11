using System.IO;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class Stage5HistoricalArtifactTests
{
    [Fact]
    public void DeviceMigration_LastPresentDate_parses_FILETIME_bytes()
    {
        var expected = new DateTimeOffset(2025, 11, 2, 14, 30, 0, TimeSpan.Zero);
        var bytes = BitConverter.GetBytes(expected.ToFileTime());

        var parsed = HistoricalForensicHelpers.TryParseLastPresentDate(bytes, out var actual);

        Assert.True(parsed);
        Assert.Equal(expected, actual);
        Assert.Contains(
            @"SYSTEM\CurrentControlSet\Control\DeviceMigration\Devices",
            HistoricalForensicHelpers.DeviceMigrationPaths());
    }

    [Fact]
    public void Select_mapping_formats_Current_Default_and_LastKnownGood()
    {
        var selection = HistoricalForensicHelpers.ParseSelect(new Dictionary<string, object?>
        {
            ["Current"] = 2,
            ["Default"] = 1L,
            ["LastKnownGood"] = 3
        });

        Assert.Equal("ControlSet002", selection.Current);
        Assert.Equal("ControlSet001", selection.Default);
        Assert.Equal("ControlSet003", selection.LastKnownGood);
    }

    [Fact]
    public void ControlSet_diff_reports_missing_identity_without_malicious_assumption()
    {
        var snapshots =
            new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyCollection<string>>>(StringComparer.OrdinalIgnoreCase)
            {
                ["ControlSet001"] = new Dictionary<string, IReadOnlyCollection<string>>
                {
                    ["USB"] = new[] { @"USB\VID_1234&PID_5678\SERIAL" },
                    ["usbflags"] = new[] { @"usbflags\123456780100" }
                },
                ["ControlSet002"] = new Dictionary<string, IReadOnlyCollection<string>>
                {
                    ["USB"] = Array.Empty<string>(),
                    ["usbflags"] = new[] { @"usbflags\123456780100" }
                }
            };

        var differences = HistoricalForensicHelpers.CompareControlSets(
            snapshots,
            new ControlSetSelection("ControlSet002", "ControlSet002", "ControlSet001"));

        var difference = Assert.Single(differences);
        Assert.Equal(@"USB\VID_1234&PID_5678\SERIAL", difference.Identity);
        Assert.True(difference.SourceIsLastKnownGood);
    }

    [Fact]
    public void Windows_old_paths_accept_root_or_Windows_directory()
    {
        var fromRoot = HistoricalForensicHelpers.BuildOfflinePaths(@"C:\Windows.old");
        var fromWindows = HistoricalForensicHelpers.BuildOfflinePaths(@"C:\Windows.old\Windows");

        Assert.Equal(@"C:\Windows.old\Windows\INF", fromRoot.InfDirectory, ignoreCase: true);
        Assert.Equal(fromRoot.SystemHive, fromWindows.SystemHive, ignoreCase: true);
        Assert.EndsWith(@"\System32\config\SOFTWARE", fromRoot.SoftwareHive, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Transaction_log_status_is_honest_when_logs_are_present()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-stage5-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var hive = Path.Combine(directory, "SYSTEM");
        try
        {
            File.WriteAllBytes(hive, [1]);
            File.WriteAllBytes(hive + ".LOG1", [2]);

            Assert.Equal(
                HistoricalForensicHelpers.TransactionLogsPresentNotReplayed,
                HistoricalForensicHelpers.GetTransactionLogStatus(hive));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12", true)]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12\", true)]
    [InlineData(@"C:\Windows", false)]
    [InlineData(@"\\server\share", false)]
    public void Vss_path_parser_accepts_only_shadow_device_paths(string candidate, bool expected)
    {
        var parsed = HistoricalForensicHelpers.TryParseShadowDevicePath(candidate, out var normalized);

        Assert.Equal(expected, parsed);
        if (expected)
        {
            Assert.EndsWith(@"\", normalized, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Snapshot_dedup_is_case_insensitive_by_hash_and_identity()
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            HistoricalForensicHelpers.SnapshotDedupKey("abc", "setupapi.dev.log")
        };

        Assert.False(keys.Add(HistoricalForensicHelpers.SnapshotDedupKey("ABC", "SETUPAPI.DEV.LOG")));
        Assert.True(keys.Add(HistoricalForensicHelpers.SnapshotDedupKey("ABC", "SYSTEM")));
    }

    [Fact]
    public void Hash_and_provenance_fields_preserve_acquisition_identity()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "stage-5-evidence", Encoding.UTF8);
            var hash = HistoricalForensicHelpers.ComputeSha256(path);
            var acquiredAt = DateTimeOffset.UtcNow;
            var evidence = new EvidenceRecord
            {
                SourceFile = path,
                SourceSha256 = hash,
                AcquisitionTimestampUtc = acquiredAt,
                Provenance = $"Read-only source path: {path}"
            };

            Assert.Equal(64, evidence.SourceSha256.Length);
            Assert.Equal(acquiredAt, evidence.AcquisitionTimestampUtc);
            Assert.Contains(path, evidence.Provenance, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
