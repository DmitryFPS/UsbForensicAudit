using System.Buffers.Binary;
using System.IO;
using System.Text;
using Microsoft.Data.Sqlite;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class Stage6ForensicArtifactTests
{
    [Fact]
    public void MruListEx_preserves_order_stops_at_terminator_and_deduplicates()
    {
        var bytes = new byte[20];
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0, 4), 3);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4, 4), 1);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), 3);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12, 4), -1);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(16, 4), 9);

        Assert.Equal(new[] { 3, 1 }, ForensicArtifactParsers.ParseMruListEx(bytes));
    }

    [Fact]
    public void Pidl_parser_extracts_bounded_path_fragment()
    {
        var text = Encoding.Unicode.GetBytes(@"E:\Evidence" + "\0");
        var data = new byte[text.Length + 4];
        BinaryPrimitives.WriteUInt16LittleEndian(data, checked((ushort)(text.Length + 2)));
        text.CopyTo(data, 2);

        var parsed = ForensicArtifactParsers.ParsePidl(data);

        Assert.Contains(parsed.PathFragments, x => x.Contains(@"E:\Evidence", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(@"E:\Evidence", parsed.BestPath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Shellbag_parser_filters_non_usb_node_and_keeps_usb_marker()
    {
        static byte[] Item(string text)
        {
            var payload = Encoding.Unicode.GetBytes(text + "\0");
            var bytes = new byte[payload.Length + 4];
            BinaryPrimitives.WriteUInt16LittleEndian(bytes, checked((ushort)(payload.Length + 2)));
            payload.CopyTo(bytes, 2);
            return bytes;
        }

        var internalNode = ForensicArtifactParsers.ParseShellBagNode(Item(@"C:\Windows"), "", 7);
        var usbNode = ForensicArtifactParsers.ParseShellBagNode(Item(@"USBSTOR\Disk\SERIAL"), "", 8);

        Assert.False(internalNode.IsUsbRelevant);
        Assert.True(usbNode.IsUsbRelevant);
        Assert.Equal(8, usbNode.Slot);
    }

    [Fact]
    public void Custom_jump_list_extracts_embedded_shell_link_fixture()
    {
        var link = new byte[0x4C];
        BinaryPrimitives.WriteUInt32LittleEndian(link, 0x4C);
        new byte[]
        {
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
        }.CopyTo(link, 4);

        var entry = Assert.Single(ForensicArtifactParsers.ParseCustomJumpList(link, "test-app"));

        Assert.Equal("test-app", entry.AppId);
        Assert.StartsWith("test-app:custom:", entry.Link.LinkPath, StringComparison.Ordinal);
    }

    [Fact]
    public void Automatic_jump_list_extracts_embedded_shell_link_fixture()
    {
        var entry = Assert.Single(
            ForensicArtifactParsers.ParseAutomaticJumpList(BuildAutomaticJumpListFixture(), "automatic-app"));

        Assert.Equal("automatic-app", entry.AppId);
        Assert.Equal("1", entry.StreamName);
        Assert.Equal("automatic-app:1", entry.Link.LinkPath);
    }

    [Fact]
    public void Pca_and_bam_helpers_preserve_execution_semantics()
    {
        Assert.Equal("Indirect",
            ExecutionArtifactCollector.ClassifyPrefetchEvidenceStrength(cleanerMatched: false));
        Assert.Equal("Direct",
            ExecutionArtifactCollector.ClassifyPrefetchEvidenceStrength(cleanerMatched: true));
        Assert.Equal("Corroborating",
            ExecutionArtifactCollector.ClassifyPcaEvidenceStrength("PcaAppLaunchDic.txt"));
        Assert.Equal("Indirect",
            ExecutionArtifactCollector.ClassifyPcaEvidenceStrength("PcaGeneralDb0.txt"));

        var expected = new DateTimeOffset(2026, 4, 5, 6, 7, 8, TimeSpan.Zero);
        var bytes = BitConverter.GetBytes(expected.ToFileTime());
        Assert.Equal(expected, ExecutionArtifactCollector.TryFileTime(bytes));
        Assert.Null(ExecutionArtifactCollector.TryFileTime([1, 2, 3]));
    }

    [Fact]
    public void Sid_mapping_falls_back_safely_for_unknown_sid()
    {
        Assert.Equal("fallback-user",
            UserArtifactCollector.ResolveAccountName("not-a-valid-sid", "fallback-user"));
    }

    [Fact]
    public void Shimcache_parser_rejects_unknown_layout_and_parses_10ts_without_execution_claim()
    {
        var unsupported = ForensicArtifactParsers.ParseShimcache(new byte[32]);
        Assert.False(unsupported.Supported);
        Assert.Contains("Unsupported", unsupported.Warning, StringComparison.OrdinalIgnoreCase);

        var pathBytes = Encoding.Unicode.GetBytes(@"\Device\HarddiskVolume3\Tools\usb.exe");
        var payloadSize = 2 + pathBytes.Length + 8;
        var data = new byte[12 + payloadSize];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 0x73743031);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8, 4), checked((uint)payloadSize));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12, 2), checked((ushort)pathBytes.Length));
        pathBytes.CopyTo(data, 14);
        BinaryPrimitives.WriteInt64LittleEndian(
            data.AsSpan(14 + pathBytes.Length, 8),
            new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero).ToFileTime());

        var parsed = ForensicArtifactParsers.ParseShimcache(data);

        Assert.True(parsed.Supported);
        var entry = Assert.Single(parsed.Entries);
        Assert.False(entry.ExecutionProven);
        Assert.Equal(@"\Device\HarddiskVolume3\Tools\usb.exe", entry.Path);
    }

    [Fact]
    public void Recycle_bin_v2_metadata_is_parsed_structurally()
    {
        var path = @"E:\Case\report.txt";
        var pathBytes = Encoding.Unicode.GetBytes(path + "\0");
        var data = new byte[28 + pathBytes.Length];
        BinaryPrimitives.WriteInt64LittleEndian(data, 2);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(8, 8), 1234);
        var deleted = new DateTimeOffset(2026, 2, 3, 4, 5, 6, TimeSpan.Zero);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(16, 8), deleted.ToFileTime());
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(24, 4), path.Length + 1);
        pathBytes.CopyTo(data, 28);

        var parsed = UserArtifactCollector.ParseRecycleMetadata(data);

        Assert.NotNull(parsed);
        Assert.Equal(path, parsed.Value.OriginalPath);
        Assert.Equal(1234, parsed.Value.Size);
        Assert.Equal(deleted, parsed.Value.DeletedUtc);
    }

    [Fact]
    public void Storage_round_trip_preserves_session_and_extended_fields()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-stage6-{Guid.NewGuid():N}");
        try
        {
            var storage = new AuditStorage(directory);
            var result = BuildResult();

            storage.Save(result);
            storage.Save(result);
            var loaded = storage.Load(result.SessionId);

            Assert.NotNull(loaded);
            Assert.Equal(result.SessionId, loaded.SessionId);
            Assert.Equal(37.5, loaded.Coverage.ExactDateCoveragePercent);

            var device = Assert.Single(loaded.Devices);
            Assert.Equal(result.SessionId, device.SessionId);
            Assert.Equal("canonical-1", device.CanonicalDeviceId);
            Assert.Equal("External", device.Classification);
            Assert.Equal("USB", device.Transport);
            Assert.Equal("VOL-123", Assert.Single(device.Volumes).VolumeSerialNumber);
            Assert.Contains("identity graph", device.IdentityProvenance);

            var evidence = Assert.Single(loaded.Evidence);
            Assert.Equal(result.SessionId, evidence.SessionId);
            Assert.Equal("Corroborating", evidence.EvidenceStrength);
            Assert.Equal("S-1-5-21-1", evidence.UserSid);
            Assert.False(evidence.CanEstablishConnectionDate);

            var cleanup = Assert.Single(loaded.CleanupFindings);
            Assert.Equal(result.SessionId, cleanup.SessionId);
            Assert.Equal("LogClearing", cleanup.ActionKind);
            Assert.Equal("event log", cleanup.Provenance);

            var report = ForensicReportBuilder.BuildHtml(loaded);
            Assert.Contains($"{loaded.Coverage.ExactDateCoveragePercent:0.##}%", report);
            Assert.Contains("Покрытие источников", report);
            Assert.Equal(5, File.ReadLines(storage.JsonlPath).Count());
            Assert.All(File.ReadLines(storage.JsonlPath), line => Assert.Contains(result.SessionId, line));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }

    [Fact]
    public void Storage_migrates_legacy_record_tables_without_data_loss()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-stage6-migration-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var database = Path.Combine(directory, "audit.sqlite");
            using (var connection = new SqliteConnection($"Data Source={database}"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE devices (id INTEGER PRIMARY KEY, collected_at_utc TEXT NOT NULL, source TEXT NOT NULL,
                        device_instance_id TEXT NOT NULL);
                    CREATE TABLE evidence (id INTEGER PRIMARY KEY, timestamp_utc TEXT NOT NULL, source TEXT NOT NULL);
                    CREATE TABLE cleanup_findings (id INTEGER PRIMARY KEY, timestamp_utc TEXT NOT NULL,
                        severity TEXT NOT NULL, area TEXT NOT NULL, finding TEXT NOT NULL);
                    INSERT INTO devices VALUES (1, '2020-01-01T00:00:00Z', 'legacy', 'USB\LEGACY');
                    """;
                command.ExecuteNonQuery();
            }

            _ = new AuditStorage(directory);

            using var migrated = new SqliteConnection($"Data Source={database}");
            migrated.Open();
            using var check = migrated.CreateCommand();
            check.CommandText = "SELECT COUNT(*), MAX(device_instance_id) FROM devices;";
            using var reader = check.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal(1, reader.GetInt32(0));
            Assert.Equal(@"USB\LEGACY", reader.GetString(1));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }

    [Fact]
    public void Coverage_tracks_status_caps_errors_and_exact_date_percentage()
    {
        var result = new AuditResult();
        result.SourceWarnings.Add("collector: достигнут лимит 4000 записей");
        AuditOrchestrator.AddCoverage(result, "UserArtifacts", 25, 0);
        result.Devices.AddRange(
        [
            new UsbDeviceRecord
            {
                CanonicalDeviceId = "one", IsCanonicalPrimary = true,
                FirstConnectedUtc = DateTimeOffset.UtcNow, ConnectionDisplayKind = "ExactEvent"
            },
            new UsbDeviceRecord { CanonicalDeviceId = "two", IsCanonicalPrimary = true },
            new UsbDeviceRecord
            {
                CanonicalDeviceId = "three", IsCanonicalPrimary = true,
                FirstConnectedUtc = DateTimeOffset.UtcNow, ConnectionDisplayKind = "PnpDevProperty"
            },
            new UsbDeviceRecord { CanonicalDeviceId = "four", IsCanonicalPrimary = true }
        ]);

        AuditOrchestrator.CalculateDateCoverage(result);

        var source = Assert.Single(result.Coverage.Sources);
        Assert.Equal("Partial", source.Status);
        Assert.True(source.Capped);
        Assert.Equal(4000, source.Limit);
        Assert.NotEmpty(source.Error);
        Assert.Equal(50, result.Coverage.ExactDateCoveragePercent);
    }

    private static AuditResult BuildResult()
    {
        var result = new AuditResult
        {
            SessionId = "stage6-session",
            StartedAtUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            FinishedAtUtc = new DateTimeOffset(2026, 1, 1, 0, 1, 0, TimeSpan.Zero),
            Coverage = new ScanCoverageReport
            {
                CanonicalDeviceCount = 8,
                CanonicalDevicesWithExactDates = 3,
                Sources = [new SourceCoverage { Source = "test", Status = "Complete", Count = 3 }]
            }
        };
        result.Devices.Add(new UsbDeviceRecord
        {
            CanonicalDeviceId = "canonical-1",
            Classification = "External",
            ClassificationConfidence = "High",
            ClassificationProvenance = ["topology"],
            Transport = "USB",
            TransportProvenance = ["USB parent"],
            Volumes = [new VolumeIdentity { VolumeSerialNumber = "VOL-123", Provenance = ["MountedDevices"] }],
            IdentityProvenance = ["identity graph"]
        });
        result.Evidence.Add(new EvidenceRecord
        {
            Source = "BAM Parsed",
            EvidenceStrength = "Corroborating",
            Confidence = "High",
            UserSid = "S-1-5-21-1",
            ResolvedUserName = "DOMAIN\\User",
            RegistryLastWriteUtc = result.StartedAtUtc,
            CanEstablishConnectionDate = false
        });
        result.CleanupFindings.Add(new CleanupFinding
        {
            ActionKind = "LogClearing",
            Assessment = "Suspicious",
            Provenance = "event log"
        });
        return result;
    }

    private static byte[] BuildAutomaticJumpListFixture()
    {
        const uint free = 0xFFFFFFFF;
        const uint end = 0xFFFFFFFE;
        var data = new byte[2048];
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

        var link = data.AsSpan(1536, 0x4C);
        BinaryPrimitives.WriteUInt32LittleEndian(link, 0x4C);
        new byte[]
        {
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
        }.CopyTo(link.Slice(4));
        return data;
    }
}
