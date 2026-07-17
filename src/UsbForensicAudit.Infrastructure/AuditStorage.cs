using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;
using Microsoft.Data.Sqlite;

namespace UsbForensicAudit;

public sealed class AuditStorage : IAuditStorage
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public string DataDirectory { get; }
    public string DatabasePath { get; }
    public string JsonlPath { get; }
    private readonly Mutex _storageMutex;

    public AuditStorage() : this(AppPaths.DataDirectory) { }

    public AuditStorage(string dataDirectory)
    {
        DataDirectory = dataDirectory;
        DatabasePath = Path.Combine(DataDirectory, "audit.sqlite");
        JsonlPath = Path.Combine(DataDirectory, "evidence.jsonl");
        var mutexId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            Path.GetFullPath(DataDirectory).ToUpperInvariant())))[..24];
        _storageMutex = new Mutex(false, $@"Local\UsbForensicAudit.Storage.{mutexId}");
        Directory.CreateDirectory(DataDirectory);
        ExecuteExclusive(Initialize);
    }

    public void Save(AuditResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        ExecuteExclusive(() =>
        {
            if (string.IsNullOrWhiteSpace(result.SessionId)) result.SessionId = Guid.NewGuid().ToString("N");
            var inserted = SaveSqlite(result);
            if (inserted)
            {
                AppendJsonl(result);
                MarkJsonlAppended(result.SessionId);
            }
            else if (!WasJsonlAppended(result.SessionId))
            {
                if (!WasSessionCompletedInJsonl(result.SessionId))
                {
                    AppendJsonl(result);
                }

                MarkJsonlAppended(result.SessionId);
            }
        });
    }

    public AuditResult? Load(string sessionId)
    {
        using var connection = Open();
        using var session = connection.CreateCommand();
        session.CommandText = """
            SELECT started_at_utc, finished_at_utc, computer_name, user_name, windows_version,
                   os_installed_at_utc, is_administrator, warnings_json, coverage_json
            FROM audit_sessions WHERE session_id=$session;
            """;
        session.Parameters.AddWithValue("$session", sessionId);
        using var reader = session.ExecuteReader();
        if (!reader.Read()) return null;
        var result = new AuditResult
        {
            SessionId = sessionId,
            StartedAtUtc = ParseDate(reader.GetString(0)),
            FinishedAtUtc = ParseDate(reader.GetString(1)),
            ComputerName = reader.GetString(2),
            UserName = reader.GetString(3),
            WindowsVersion = reader.GetString(4),
            OsInstalledAtUtc = reader.IsDBNull(5) ? null : ParseDate(reader.GetString(5)),
            IsAdministrator = reader.GetInt64(6) != 0,
            Coverage = Deserialize<ScanCoverageReport>(reader.IsDBNull(8) ? "" : reader.GetString(8)) ?? new()
        };
        foreach (var warning in Deserialize<List<string>>(reader.IsDBNull(7) ? "" : reader.GetString(7)) ?? [])
            result.SourceWarnings.Add(warning);
        reader.Close();
        LoadRecords(connection, "devices", sessionId, json => Deserialize<UsbDeviceRecord>(json), result.Devices);
        LoadRecords(connection, "evidence", sessionId, json => Deserialize<EvidenceRecord>(json), result.Evidence);
        LoadRecords(connection, "cleanup_findings", sessionId, json => Deserialize<CleanupFinding>(json), result.CleanupFindings);
        return result;
    }

    private void Initialize()
    {
        using var connection = Open();
        Execute(connection, """
            CREATE TABLE IF NOT EXISTS audit_sessions (
                session_id TEXT PRIMARY KEY,
                started_at_utc TEXT NOT NULL,
                finished_at_utc TEXT NOT NULL,
                computer_name TEXT NOT NULL,
                user_name TEXT NOT NULL,
                windows_version TEXT NOT NULL,
                os_installed_at_utc TEXT,
                is_administrator INTEGER NOT NULL,
                warnings_json TEXT NOT NULL,
                coverage_json TEXT NOT NULL,
                jsonl_appended INTEGER NOT NULL DEFAULT 0
            );
            """);
        Execute(connection, """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                collected_at_utc TEXT NOT NULL,
                source TEXT NOT NULL,
                device_instance_id TEXT NOT NULL,
                device_type TEXT, vid TEXT, pid TEXT, serial TEXT, friendly_name TEXT,
                manufacturer TEXT, product TEXT, location_information TEXT, location_paths TEXT,
                transport TEXT, transport_confidence TEXT, connection TEXT, connection_confidence TEXT,
                classification TEXT, classification_confidence TEXT, classification_provenance TEXT,
                hardware_ids TEXT, compatible_ids TEXT, raw_json TEXT
            );
            """);
        Execute(connection, """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL, source TEXT NOT NULL, provider TEXT, channel TEXT,
                record_id INTEGER, computer TEXT, source_file TEXT, source_record TEXT,
                evidence_category TEXT, user_explanation TEXT, event_id TEXT, level TEXT,
                device_hint TEXT, summary TEXT, raw_text TEXT, acquisition_timestamp_utc TEXT,
                source_sha256 TEXT, provenance TEXT
            );
            """);
        Execute(connection, """
            CREATE TABLE IF NOT EXISTS cleanup_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL, severity TEXT NOT NULL, area TEXT NOT NULL,
                finding TEXT NOT NULL, details TEXT
            );
            """);

        EnsureColumns(connection, "devices", new Dictionary<string, string>
        {
            ["session_id"] = "TEXT", ["record_key"] = "TEXT", ["record_json"] = "TEXT",
            ["canonical_device_id"] = "TEXT", ["classification"] = "TEXT", ["classification_confidence"] = "TEXT",
            ["classification_provenance"] = "TEXT", ["transport"] = "TEXT", ["transport_confidence"] = "TEXT",
            ["connection"] = "TEXT", ["connection_confidence"] = "TEXT", ["hardware_ids"] = "TEXT",
            ["compatible_ids"] = "TEXT", ["volumes_json"] = "TEXT", ["identity_provenance_json"] = "TEXT"
        });
        EnsureColumns(connection, "evidence", new Dictionary<string, string>
        {
            ["session_id"] = "TEXT", ["record_key"] = "TEXT", ["record_json"] = "TEXT",
            ["provider"] = "TEXT", ["channel"] = "TEXT", ["record_id"] = "INTEGER", ["computer"] = "TEXT",
            ["source_file"] = "TEXT", ["source_record"] = "TEXT", ["evidence_category"] = "TEXT",
            ["user_explanation"] = "TEXT", ["acquisition_timestamp_utc"] = "TEXT", ["source_sha256"] = "TEXT",
            ["provenance"] = "TEXT", ["evidence_strength"] = "TEXT", ["confidence"] = "TEXT",
            ["user_sid"] = "TEXT", ["resolved_user_name"] = "TEXT", ["registry_last_write_utc"] = "TEXT",
            ["can_establish_connection_date"] = "INTEGER"
        });
        EnsureColumns(connection, "cleanup_findings", new Dictionary<string, string>
        {
            ["session_id"] = "TEXT", ["record_key"] = "TEXT", ["record_json"] = "TEXT",
            ["assessment"] = "TEXT", ["initiator_kind"] = "TEXT", ["initiator_account"] = "TEXT",
            ["possible_tool"] = "TEXT", ["confidence"] = "TEXT", ["action_kind"] = "TEXT",
            ["provenance"] = "TEXT"
        });
        Execute(connection, "CREATE UNIQUE INDEX IF NOT EXISTS ux_devices_session_record ON devices(session_id, record_key) WHERE session_id IS NOT NULL;");
        Execute(connection, "CREATE UNIQUE INDEX IF NOT EXISTS ux_evidence_session_record ON evidence(session_id, record_key) WHERE session_id IS NOT NULL;");
        Execute(connection, "CREATE UNIQUE INDEX IF NOT EXISTS ux_cleanup_session_record ON cleanup_findings(session_id, record_key) WHERE session_id IS NOT NULL;");
    }

    private bool SaveSqlite(AuditResult result)
    {
        using var connection = Open();
        using var tx = connection.BeginTransaction();
        using (var insert = connection.CreateCommand())
        {
            insert.Transaction = tx;
            insert.CommandText = """
                INSERT OR IGNORE INTO audit_sessions (
                    session_id, started_at_utc, finished_at_utc, computer_name, user_name, windows_version,
                    os_installed_at_utc, is_administrator, warnings_json, coverage_json)
                VALUES ($id,$started,$finished,$computer,$user,$windows,$installed,$admin,$warnings,$coverage);
                """;
            insert.Parameters.AddWithValue("$id", result.SessionId);
            insert.Parameters.AddWithValue("$started", result.StartedAtUtc.ToString("O"));
            insert.Parameters.AddWithValue("$finished", result.FinishedAtUtc.ToString("O"));
            insert.Parameters.AddWithValue("$computer", result.ComputerName);
            insert.Parameters.AddWithValue("$user", result.UserName);
            insert.Parameters.AddWithValue("$windows", result.WindowsVersion);
            insert.Parameters.AddWithValue("$installed", (object?)result.OsInstalledAtUtc?.ToString("O") ?? DBNull.Value);
            insert.Parameters.AddWithValue("$admin", result.IsAdministrator ? 1 : 0);
            insert.Parameters.AddWithValue("$warnings", JsonSerializer.Serialize(result.SourceWarnings, JsonOptions));
            insert.Parameters.AddWithValue("$coverage", JsonSerializer.Serialize(result.Coverage, JsonOptions));
            if (insert.ExecuteNonQuery() == 0)
            {
                tx.Rollback();
                return false;
            }
        }

        foreach (var item in result.Devices)
        {
            item.SessionId = result.SessionId;
            item.RawJson = string.IsNullOrWhiteSpace(item.RawJson) ? "{}" : item.RawJson;
            var json = JsonSerializer.Serialize(item, JsonOptions);
            InsertDevice(connection, tx, result.SessionId, item, json);
        }
        foreach (var item in result.Evidence)
        {
            item.SessionId = result.SessionId;
            InsertEvidence(connection, tx, result.SessionId, item, JsonSerializer.Serialize(item, JsonOptions));
        }
        foreach (var item in result.CleanupFindings)
        {
            item.SessionId = result.SessionId;
            InsertCleanup(connection, tx, result.SessionId, item, JsonSerializer.Serialize(item, JsonOptions));
        }
        tx.Commit();
        return true;
    }

    private static void InsertDevice(SqliteConnection c, SqliteTransaction tx, string sessionId, UsbDeviceRecord x, string json)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT OR IGNORE INTO devices (
              session_id,record_key,record_json,collected_at_utc,source,device_instance_id,device_type,vid,pid,serial,
              friendly_name,manufacturer,product,location_information,location_paths,transport,transport_confidence,
              connection,connection_confidence,classification,classification_confidence,classification_provenance,
              hardware_ids,compatible_ids,raw_json,canonical_device_id,volumes_json,identity_provenance_json)
            VALUES ($s,$k,$j,$at,$source,$id,$type,$vid,$pid,$serial,$friendly,$manufacturer,$product,$li,$lp,$transport,
              $tc,$connection,$cc,$class,$classc,$classp,$hardware,$compatible,$raw,$canonical,$volumes,$identity);
            """;
        Add(cmd, "$s", sessionId, "$k", HashKey(json), "$j", json, "$at", x.CollectedAtUtc.ToString("O"),
            "$source", x.Source, "$id", x.DeviceInstanceId, "$type", x.DeviceType, "$vid", x.Vid, "$pid", x.Pid,
            "$serial", x.Serial, "$friendly", x.FriendlyName, "$manufacturer", x.Manufacturer, "$product", x.Product,
            "$li", x.LocationInformation, "$lp", x.LocationPaths, "$transport", x.Transport, "$tc", x.TransportConfidence,
            "$connection", x.Connection, "$cc", x.ConnectionConfidence, "$class", x.Classification,
            "$classc", x.ClassificationConfidence, "$classp", x.ClassificationEvidenceText, "$hardware", x.HardwareIds,
            "$compatible", x.CompatibleIds, "$raw", x.RawJson, "$canonical", x.CanonicalDeviceId,
            "$volumes", JsonSerializer.Serialize(x.Volumes, JsonOptions),
            "$identity", JsonSerializer.Serialize(x.IdentityProvenance, JsonOptions));
        cmd.ExecuteNonQuery();
    }

    private static void InsertEvidence(SqliteConnection c, SqliteTransaction tx, string sessionId, EvidenceRecord x, string json)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT OR IGNORE INTO evidence (
              session_id,record_key,record_json,timestamp_utc,source,provider,channel,record_id,computer,source_file,
              source_record,evidence_category,user_explanation,event_id,level,device_hint,summary,raw_text,
              acquisition_timestamp_utc,source_sha256,provenance,evidence_strength,confidence,user_sid,
              resolved_user_name,registry_last_write_utc,can_establish_connection_date)
            VALUES ($s,$k,$j,$at,$source,$provider,$channel,$rid,$computer,$file,$record,$category,$explanation,$event,
              $level,$hint,$summary,$raw,$acquired,$sha,$provenance,$strength,$confidence,$sid,$username,$lastwrite,$date);
            """;
        Add(cmd, "$s", sessionId, "$k", HashKey(json), "$j", json, "$at", x.TimestampUtc.ToString("O"),
            "$source", x.Source, "$provider", x.Provider, "$channel", x.Channel, "$rid", (object?)x.RecordId ?? DBNull.Value,
            "$computer", x.Computer, "$file", x.SourceFile, "$record", x.SourceRecord, "$category", x.EvidenceCategory,
            "$explanation", x.UserExplanation, "$event", x.EventId, "$level", x.Level, "$hint", x.DeviceHint,
            "$summary", x.Summary, "$raw", x.RawText, "$acquired", x.AcquisitionTimestampUtc.ToString("O"),
            "$sha", x.SourceSha256, "$provenance", x.Provenance, "$strength", x.EvidenceStrength,
            "$confidence", x.Confidence, "$sid", x.UserSid, "$username", x.ResolvedUserName,
            "$lastwrite", (object?)x.RegistryLastWriteUtc?.ToString("O") ?? DBNull.Value,
            "$date", x.CanEstablishConnectionDate ? 1 : 0);
        cmd.ExecuteNonQuery();
    }

    private static void InsertCleanup(SqliteConnection c, SqliteTransaction tx, string sessionId, CleanupFinding x, string json)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT OR IGNORE INTO cleanup_findings (
              session_id,record_key,record_json,timestamp_utc,severity,area,finding,details,assessment,initiator_kind,
              initiator_account,possible_tool,confidence,action_kind,provenance)
            VALUES ($s,$k,$j,$at,$severity,$area,$finding,$details,$assessment,$ik,$ia,$tool,$confidence,$action,$provenance);
            """;
        Add(cmd, "$s", sessionId, "$k", HashKey(json), "$j", json, "$at", x.TimestampUtc.ToString("O"),
            "$severity", x.Severity, "$area", x.Area, "$finding", x.Finding, "$details", x.Details,
            "$assessment", x.Assessment, "$ik", x.InitiatorKind, "$ia", x.InitiatorAccount,
            "$tool", x.PossibleTool, "$confidence", x.Confidence, "$action", x.ActionKind, "$provenance", x.Provenance);
        cmd.ExecuteNonQuery();
    }

    private void AppendJsonl(AuditResult result)
    {
        var previousHash = ReadLastHash();
        using var stream = new FileStream(JsonlPath, FileMode.Append, FileAccess.Write, FileShare.Read);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true);
        var sessionMetadata = new
        {
            result.SessionId, result.StartedAtUtc, result.FinishedAtUtc, result.ComputerName,
            result.UserName, result.WindowsVersion, result.OsInstalledAtUtc, result.IsAdministrator,
            result.SourceWarnings, result.Coverage
        };
        foreach (var (type, item) in new[] { ("AuditSession", (object)sessionMetadata) }
                     .Concat(result.Devices.Select(x => ("UsbDeviceRecord", (object)x)))
                     .Concat(result.Evidence.Select(x => ("EvidenceRecord", (object)x)))
                     .Concat(result.CleanupFindings.Select(x => ("CleanupFinding", (object)x)))
                     .Concat(new[]
                     {
                         ("AuditSessionComplete", (object)new
                         {
                             recordCount = 1 + result.Devices.Count + result.Evidence.Count + result.CleanupFindings.Count
                         })
                     }))
        {
            var payload = JsonSerializer.Serialize(new { sessionId = result.SessionId, recordType = type, previousHash, data = item }, JsonOptions);
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
            writer.WriteLine(JsonSerializer.Serialize(new
            {
                sessionId = result.SessionId, recordType = type, previousHash, recordHash = hash, data = item
            }, JsonOptions));
            previousHash = hash;
        }
        writer.Flush();
        stream.Flush(flushToDisk: true);
    }

    private string ReadLastHash()
    {
        if (!File.Exists(JsonlPath)) return "";
        var last = ReadLastNonEmptyLine(JsonlPath);
        if (string.IsNullOrWhiteSpace(last)) return "";
        try
        {
            using var doc = JsonDocument.Parse(last);
            return doc.RootElement.TryGetProperty("recordHash", out var hash) ? hash.GetString() ?? "" : "";
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            throw new InvalidDataException(
                "Последняя запись evidence.jsonl повреждена; продолжение нарушило бы hash-chain.",
                exception);
        }
    }

    private void MarkJsonlAppended(string sessionId)
    {
        using var connection = Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "UPDATE audit_sessions SET jsonl_appended=1 WHERE session_id=$id;";
        cmd.Parameters.AddWithValue("$id", sessionId);
        cmd.ExecuteNonQuery();
    }

    private bool WasJsonlAppended(string sessionId)
    {
        using var connection = Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT jsonl_appended FROM audit_sessions WHERE session_id=$id;";
        cmd.Parameters.AddWithValue("$id", sessionId);
        return Convert.ToInt64(cmd.ExecuteScalar() ?? 0L) != 0;
    }

    private bool WasSessionCompletedInJsonl(string sessionId)
    {
        if (!File.Exists(JsonlPath))
        {
            return false;
        }

        foreach (var line in File.ReadLines(JsonlPath))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                if (root.TryGetProperty("sessionId", out var storedSession)
                    && root.TryGetProperty("recordType", out var recordType)
                    && storedSession.ValueEquals(sessionId)
                    && recordType.ValueEquals("AuditSessionComplete"))
                {
                    return true;
                }
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException(
                    "evidence.jsonl содержит повреждённую запись; автоматический повтор сохранения остановлен.",
                    exception);
            }
        }

        return false;
    }

    private static void LoadRecords<T>(
        SqliteConnection connection, string table, string sessionId, Func<string, T?> deserialize, List<T> target)
        where T : class
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = $"SELECT record_json FROM {table} WHERE session_id=$session ORDER BY id;";
        cmd.Parameters.AddWithValue("$session", sessionId);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            if (!reader.IsDBNull(0) && deserialize(reader.GetString(0)) is { } item) target.Add(item);
        }
    }

    private static void EnsureColumns(SqliteConnection connection, string table, IReadOnlyDictionary<string, string> columns)
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = $"PRAGMA table_info({table});";
            using var reader = cmd.ExecuteReader();
            while (reader.Read()) existing.Add(reader.GetString(1));
        }
        foreach (var (name, type) in columns)
            if (!existing.Contains(name)) Execute(connection, $"ALTER TABLE {table} ADD COLUMN {name} {type};");
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection($"Data Source={DatabasePath};Default Timeout=30;Pooling=True");
        connection.Open();
        using var timeout = connection.CreateCommand();
        timeout.CommandText = "PRAGMA busy_timeout=30000;";
        timeout.ExecuteNonQuery();
        return connection;
    }

    private void ExecuteExclusive(Action action)
    {
        var lockTaken = false;
        try
        {
            try
            {
                lockTaken = _storageMutex.WaitOne(TimeSpan.FromSeconds(30));
            }
            catch (AbandonedMutexException)
            {
                lockTaken = true;
            }

            if (!lockTaken)
            {
                throw new TimeoutException("Хранилище аудита занято другим процессом более 30 секунд.");
            }

            action();
        }
        finally
        {
            if (lockTaken)
            {
                _storageMutex.ReleaseMutex();
            }
        }
    }

    private static string? ReadLastNonEmptyLine(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (stream.Length == 0)
        {
            return null;
        }

        var bytes = new List<byte>();
        var foundContent = false;
        var buffer = new byte[4096];
        var position = stream.Length;
        while (position > 0)
        {
            var count = (int)Math.Min(buffer.Length, position);
            position -= count;
            stream.Position = position;
            var read = stream.Read(buffer, 0, count);
            for (var index = read - 1; index >= 0; index--)
            {
                var value = buffer[index];
                if (!foundContent && value is (byte)'\r' or (byte)'\n')
                {
                    continue;
                }

                foundContent = true;
                if (value == (byte)'\n')
                {
                    bytes.Reverse();
                    return Encoding.UTF8.GetString(bytes.ToArray()).TrimEnd('\r');
                }

                bytes.Add(value);
            }
        }

        bytes.Reverse();
        return Encoding.UTF8.GetString(bytes.ToArray()).TrimEnd('\r');
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private static void Add(SqliteCommand cmd, params object[] pairs)
    {
        for (var i = 0; i < pairs.Length; i += 2)
            cmd.Parameters.AddWithValue((string)pairs[i], pairs[i + 1] ?? DBNull.Value);
    }

    private static string HashKey(string json) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
    private static T? Deserialize<T>(string json) =>
        string.IsNullOrWhiteSpace(json) ? default : JsonSerializer.Deserialize<T>(json, JsonOptions);
    private static DateTimeOffset ParseDate(string value) =>
        DateTimeOffset.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
}
