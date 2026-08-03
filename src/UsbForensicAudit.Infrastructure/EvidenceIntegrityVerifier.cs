using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace UsbForensicAudit;

/// <summary>
/// Верификатор целостности доказательной базы. Пересчитывает hash-chain
/// журнала evidence.jsonl запись за записью и сверяет итоговые хеши сессий
/// с печатями, сохранёнными в audit.sqlite: любая правка, удаление или
/// вставка записи задним числом разрывает цепочку или расходится с печатью.
/// </summary>
public sealed class EvidenceIntegrityVerifier : IEvidenceIntegrityVerifier
{
    private readonly IAuditStorage _storage;

    public EvidenceIntegrityVerifier(IAuditStorage storage)
    {
        _storage = storage;
    }

    public IntegrityReport Verify()
    {
        var jsonlPath = Path.Combine(_storage.DataDirectory, "evidence.jsonl");
        if (!File.Exists(jsonlPath))
        {
            return new IntegrityReport { JournalMissing = true };
        }

        var chain = VerifyChain(File.ReadLines(jsonlPath));
        var seals = ReadSeals(_storage.DatabasePath);
        var checks = new List<SessionSealCheck>();
        foreach (var (sessionId, journalHash) in chain.SessionFinalHashes)
        {
            var stored = seals.GetValueOrDefault(sessionId);
            checks.Add(new SessionSealCheck
            {
                SessionId = sessionId,
                JournalHash = journalHash,
                StoredSeal = stored,
                Status = stored is null ? SealStatus.NotSealed
                    : string.Equals(stored, journalHash, StringComparison.OrdinalIgnoreCase)
                        ? SealStatus.Match
                        : SealStatus.Mismatch
            });
        }

        return new IntegrityReport
        {
            TotalRecords = chain.TotalRecords,
            ChainBreaks = chain.Breaks,
            SealChecks = checks
        };
    }

    /// <summary>
    /// Пересчёт hash-chain по строкам журнала. Каждая запись обязана ссылаться
    /// на хеш предыдущей, а её собственный хеш — совпадать с SHA-256 полезной
    /// нагрузки. Чистая функция: тестируется без файлов и без Windows.
    /// </summary>
    public static ChainVerificationResult VerifyChain(IEnumerable<string> lines)
    {
        var breaks = new List<ChainBreak>();
        var finalHashes = new Dictionary<string, string>(StringComparer.Ordinal);
        var expectedPrevious = "";
        // После повреждённой строки следующий целый record нельзя сверить с
        // предыдущим звеном (его хеш неизвестен) — иначе он всегда помечался бы
        // ложным разрывом. Пропускаем ровно одну проверку связи и продолжаем.
        var resyncAfterCorrupt = false;
        var total = 0;
        var lineNumber = 0;
        foreach (var line in lines)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            total++;
            string sessionId, recordType, previousHash, recordHash, dataRaw;
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                sessionId = root.GetProperty("sessionId").GetString() ?? "";
                recordType = root.GetProperty("recordType").GetString() ?? "";
                previousHash = root.GetProperty("previousHash").GetString() ?? "";
                recordHash = root.GetProperty("recordHash").GetString() ?? "";
                dataRaw = root.GetProperty("data").GetRawText();
            }
            catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException)
            {
                breaks.Add(new ChainBreak
                {
                    LineNumber = lineNumber,
                    Reason = "Запись повреждена или не соответствует формату журнала."
                });
                // Дальше сверять цепочку не с чем: хеш повреждённой записи неизвестен.
                expectedPrevious = "";
                resyncAfterCorrupt = true;
                continue;
            }

            if (resyncAfterCorrupt)
            {
                // Первая целая запись после повреждённой: связь с предыдущим
                // звеном проверить нельзя, но собственный хеш записи ниже
                // проверяется, и с этой записи цепочка продолжается заново.
                resyncAfterCorrupt = false;
            }
            else if (!string.Equals(previousHash, expectedPrevious, StringComparison.OrdinalIgnoreCase))
            {
                breaks.Add(new ChainBreak
                {
                    LineNumber = lineNumber,
                    Reason = "Ссылка на предыдущую запись не совпадает: записи удалены, вставлены или переставлены."
                });
            }

            // Полезная нагрузка восстанавливается из сырых фрагментов исходной
            // строки: System.Text.Json сериализует без пробелов и в порядке
            // объявления свойств, поэтому байты совпадают с оригиналом.
            var payload = "{\"sessionId\":" + JsonSerializer.Serialize(sessionId)
                          + ",\"recordType\":" + JsonSerializer.Serialize(recordType)
                          + ",\"previousHash\":" + JsonSerializer.Serialize(previousHash)
                          + ",\"data\":" + dataRaw + "}";
            var computed = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
            if (!string.Equals(computed, recordHash, StringComparison.OrdinalIgnoreCase))
            {
                breaks.Add(new ChainBreak
                {
                    LineNumber = lineNumber,
                    Reason = "Хеш записи не совпадает с содержимым: запись изменена после создания."
                });
            }

            if (recordType == "AuditSessionComplete")
            {
                finalHashes[sessionId] = recordHash;
            }

            expectedPrevious = recordHash;
        }

        return new ChainVerificationResult
        {
            TotalRecords = total,
            Breaks = breaks,
            SessionFinalHashes = finalHashes
        };
    }

    private static Dictionary<string, string?> ReadSeals(string databasePath)
    {
        var seals = new Dictionary<string, string?>(StringComparer.Ordinal);
        if (!File.Exists(databasePath))
        {
            return seals;
        }

        using var connection = new SqliteConnection($"Data Source={databasePath};Mode=ReadOnly;Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT session_id, seal_hash FROM audit_sessions;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            seals[reader.GetString(0)] = reader.IsDBNull(1) ? null : reader.GetString(1);
        }

        return seals;
    }
}

/// <summary>Результат пересчёта hash-chain журнала доказательств.</summary>
public sealed class ChainVerificationResult
{
    public int TotalRecords { get; init; }

    public IReadOnlyList<ChainBreak> Breaks { get; init; } = [];

    /// <summary>Итоговый хеш каждой завершённой сессии в журнале.</summary>
    public IReadOnlyDictionary<string, string> SessionFinalHashes { get; init; } =
        new Dictionary<string, string>();
}
