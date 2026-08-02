using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Тесты пересчёта hash-chain журнала доказательств. Строки журнала строятся
/// тем же алгоритмом, что в AuditStorage.AppendJsonl: полезная нагрузка без
/// recordHash хешируется SHA-256, затем хеш добавляется в запись.
/// </summary>
public sealed class EvidenceIntegrityVerifierTests
{
    [Fact]
    public void VerifyChain_ValidJournal_NoBreaks()
    {
        var lines = BuildJournal("s1", 3);

        var result = EvidenceIntegrityVerifier.VerifyChain(lines);

        Assert.Equal(3, result.TotalRecords);
        Assert.Empty(result.Breaks);
    }

    [Fact]
    public void VerifyChain_EmptyJournal_NoRecordsNoBreaks()
    {
        var result = EvidenceIntegrityVerifier.VerifyChain([]);

        Assert.Equal(0, result.TotalRecords);
        Assert.Empty(result.Breaks);
    }

    [Fact]
    public void VerifyChain_TamperedData_ReportsHashMismatch()
    {
        var lines = BuildJournal("s1", 3);
        // Правка содержимого записи задним числом: хеш перестаёт совпадать.
        lines[1] = lines[1].Replace("\"index\":1", "\"index\":99", StringComparison.Ordinal);

        var result = EvidenceIntegrityVerifier.VerifyChain(lines);

        Assert.Contains(result.Breaks, static b => b.LineNumber == 2);
    }

    [Fact]
    public void VerifyChain_DeletedRecord_ReportsBrokenLink()
    {
        var lines = BuildJournal("s1", 3);
        lines.RemoveAt(1);

        var result = EvidenceIntegrityVerifier.VerifyChain(lines);

        // Третья запись (теперь вторая строка) ссылается на хеш удалённой.
        Assert.Contains(result.Breaks, static b => b.LineNumber == 2);
    }

    [Fact]
    public void VerifyChain_CorruptedLine_ReportsBreakAndContinues()
    {
        var lines = BuildJournal("s1", 3);
        lines[0] = "{ повреждённая запись";

        var result = EvidenceIntegrityVerifier.VerifyChain(lines);

        Assert.Contains(result.Breaks, static b => b.LineNumber == 1);
        Assert.Equal(3, result.TotalRecords);
    }

    [Fact]
    public void VerifyChain_CompleteRecord_CapturesSessionFinalHash()
    {
        var lines = BuildJournal("s1", 2, completeSession: true);

        var result = EvidenceIntegrityVerifier.VerifyChain(lines);

        Assert.Empty(result.Breaks);
        Assert.True(result.SessionFinalHashes.ContainsKey("s1"));

        using var document = JsonDocument.Parse(lines[^1]);
        var lastHash = document.RootElement.GetProperty("recordHash").GetString();
        Assert.Equal(lastHash, result.SessionFinalHashes["s1"]);
    }

    [Fact]
    public void VerifyChain_SkipsBlankLines()
    {
        var lines = BuildJournal("s1", 2);
        lines.Insert(1, "");

        var result = EvidenceIntegrityVerifier.VerifyChain(lines);

        Assert.Equal(2, result.TotalRecords);
        Assert.Empty(result.Breaks);
    }

    [Fact]
    public void Verify_JournalMissing_ReportsMissing()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-verify-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var verifier = new EvidenceIntegrityVerifier(new FakeStorage(directory));

            var report = verifier.Verify();

            Assert.True(report.JournalMissing);
            Assert.False(report.IsIntact);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Verify_SealedSessionMatchesJournal_IsIntact()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-verify-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var lines = BuildJournal("s1", 3, completeSession: true);
            File.WriteAllLines(Path.Combine(directory, "evidence.jsonl"), lines);

            using var document = JsonDocument.Parse(lines[^1]);
            var seal = document.RootElement.GetProperty("recordHash").GetString()!;
            CreateDatabase(Path.Combine(directory, "audit.sqlite"), "s1", seal);

            var report = new EvidenceIntegrityVerifier(new FakeStorage(directory)).Verify();

            Assert.True(report.IsIntact);
            var check = Assert.Single(report.SealChecks);
            Assert.Equal(SealStatus.Match, check.Status);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Verify_SealMismatch_ReportsViolation()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-verify-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var lines = BuildJournal("s1", 3, completeSession: true);
            File.WriteAllLines(Path.Combine(directory, "evidence.jsonl"), lines);
            CreateDatabase(Path.Combine(directory, "audit.sqlite"), "s1", "ФАЛЬШИВАЯ_ПЕЧАТЬ");

            var report = new EvidenceIntegrityVerifier(new FakeStorage(directory)).Verify();

            Assert.False(report.IsIntact);
            var check = Assert.Single(report.SealChecks);
            Assert.Equal(SealStatus.Mismatch, check.Status);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Verify_SessionWithoutSeal_ReportsNotSealedButIntact()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-verify-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var lines = BuildJournal("s1", 2, completeSession: true);
            File.WriteAllLines(Path.Combine(directory, "evidence.jsonl"), lines);
            CreateDatabase(Path.Combine(directory, "audit.sqlite"), "s1", seal: null);

            var report = new EvidenceIntegrityVerifier(new FakeStorage(directory)).Verify();

            // Сессии, записанные до внедрения печатей, не считаются нарушением.
            Assert.True(report.IsIntact);
            var check = Assert.Single(report.SealChecks);
            Assert.Equal(SealStatus.NotSealed, check.Status);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    private static void CreateDatabase(string path, string sessionId, string? seal)
    {
        using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path}");
        connection.Open();
        using var create = connection.CreateCommand();
        create.CommandText = "CREATE TABLE audit_sessions (session_id TEXT PRIMARY KEY, seal_hash TEXT);";
        create.ExecuteNonQuery();
        using var insert = connection.CreateCommand();
        insert.CommandText = "INSERT INTO audit_sessions (session_id, seal_hash) VALUES ($id, $seal);";
        insert.Parameters.AddWithValue("$id", sessionId);
        insert.Parameters.AddWithValue("$seal", (object?)seal ?? DBNull.Value);
        insert.ExecuteNonQuery();
    }

    /// <summary>Минимальная заглушка хранилища: только пути, без записи.</summary>
    private sealed class FakeStorage : IAuditStorage
    {
        public FakeStorage(string directory)
        {
            DataDirectory = directory;
            DatabasePath = Path.Combine(directory, "audit.sqlite");
        }

        public string DataDirectory { get; }

        public string DatabasePath { get; }

        public void Save(AuditResult result) => throw new NotSupportedException();

        public void SaveNetworkEnvironment(string sessionId, NetworkEnvironmentSnapshot snapshot) =>
            throw new NotSupportedException();

        public AuditResult? Load(string sessionId) => throw new NotSupportedException();

        public IReadOnlyList<SessionSummary> ListSessions() => throw new NotSupportedException();
    }

    /// <summary>Строит корректный журнал тем же алгоритмом, что боевой код.</summary>
    private static List<string> BuildJournal(string sessionId, int records, bool completeSession = false)
    {
        var lines = new List<string>();
        var previousHash = "";
        for (var i = 0; i < records; i++)
        {
            var isLast = completeSession && i == records - 1;
            var recordType = isLast ? "AuditSessionComplete" : "EvidenceRecord";
            object data = isLast ? new { recordCount = records } : new { index = i, value = $"запись {i}" };
            var payload = JsonSerializer.Serialize(new { sessionId, recordType, previousHash, data });
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
            lines.Add(JsonSerializer.Serialize(new { sessionId, recordType, previousHash, recordHash = hash, data }));
            previousHash = hash;
        }

        return lines;
    }
}
