using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;
using Microsoft.Data.Sqlite;

namespace UsbForensicAudit;

public sealed class AuditStorage : IAuditStorage
{
    public string DataDirectory { get; }
    public string DatabasePath { get; }
    public string JsonlPath { get; }

    public AuditStorage()
    {
        DataDirectory = AppPaths.DataDirectory;
        DatabasePath = Path.Combine(DataDirectory, "audit.sqlite");
        JsonlPath = Path.Combine(DataDirectory, "evidence.jsonl");
        Directory.CreateDirectory(DataDirectory);
        Initialize();
    }

    public void Save(AuditResult result)
    {
        SaveSqlite(result);
        AppendJsonl(result);
    }

    private void Initialize()
    {
        using var connection = new SqliteConnection($"Data Source={DatabasePath}");
        connection.Open();

        Execute(connection, """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                collected_at_utc TEXT NOT NULL,
                source TEXT NOT NULL,
                device_instance_id TEXT NOT NULL,
                device_type TEXT,
                vid TEXT,
                pid TEXT,
                serial TEXT,
                friendly_name TEXT,
                manufacturer TEXT,
                product TEXT,
                location_information TEXT,
                location_paths TEXT,
                transport TEXT,
                transport_confidence TEXT,
                connection TEXT,
                connection_confidence TEXT,
                classification TEXT,
                classification_confidence TEXT,
                classification_provenance TEXT,
                hardware_ids TEXT,
                compatible_ids TEXT,
                raw_json TEXT
            );
            """);

        Execute(connection, """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                source TEXT NOT NULL,
                provider TEXT,
                channel TEXT,
                record_id INTEGER,
                computer TEXT,
                source_file TEXT,
                source_record TEXT,
                evidence_category TEXT,
                user_explanation TEXT,
                event_id TEXT,
                level TEXT,
                device_hint TEXT,
                summary TEXT,
                raw_text TEXT,
                acquisition_timestamp_utc TEXT,
                source_sha256 TEXT,
                provenance TEXT
            );
            """);

        EnsureDeviceColumns(connection);
        EnsureEvidenceColumns(connection);

        Execute(connection, """
            CREATE TABLE IF NOT EXISTS cleanup_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                severity TEXT NOT NULL,
                area TEXT NOT NULL,
                finding TEXT NOT NULL,
                details TEXT
            );
            """);
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static void EnsureEvidenceColumns(SqliteConnection connection)
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        {
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA table_info(evidence);";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                existing.Add(reader.GetString(1));
            }
        }

        foreach (var (name, type) in new[]
                 {
                     ("provider", "TEXT"),
                     ("channel", "TEXT"),
                     ("record_id", "INTEGER"),
                     ("computer", "TEXT"),
                     ("source_file", "TEXT"),
                     ("source_record", "TEXT"),
                     ("evidence_category", "TEXT"),
                     ("user_explanation", "TEXT"),
                     ("acquisition_timestamp_utc", "TEXT"),
                     ("source_sha256", "TEXT"),
                     ("provenance", "TEXT")
                 })
        {
            if (!existing.Contains(name))
            {
                Execute(connection, $"ALTER TABLE evidence ADD COLUMN {name} {type};");
            }
        }
    }

    private static void EnsureDeviceColumns(SqliteConnection connection)
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "PRAGMA table_info(devices);";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                existing.Add(reader.GetString(1));
            }
        }

        foreach (var name in new[]
                 {
                     "transport", "transport_confidence", "connection", "connection_confidence",
                     "classification", "classification_confidence", "classification_provenance",
                     "hardware_ids", "compatible_ids"
                 })
        {
            if (!existing.Contains(name))
            {
                Execute(connection, $"ALTER TABLE devices ADD COLUMN {name} TEXT;");
            }
        }
    }

    private void SaveSqlite(AuditResult result)
    {
        using var connection = new SqliteConnection($"Data Source={DatabasePath}");
        connection.Open();
        using var tx = connection.BeginTransaction();

        foreach (var device in result.Devices)
        {
            using var command = connection.CreateCommand();
            command.Transaction = tx;
            command.CommandText = """
                INSERT INTO devices (
                    collected_at_utc, source, device_instance_id, device_type, vid, pid, serial,
                    friendly_name, manufacturer, product, location_information, location_paths,
                    transport, transport_confidence, connection, connection_confidence,
                    classification, classification_confidence, classification_provenance,
                    hardware_ids, compatible_ids, raw_json)
                VALUES (
                    $collected_at_utc, $source, $device_instance_id, $device_type, $vid, $pid, $serial,
                    $friendly_name, $manufacturer, $product, $location_information, $location_paths,
                    $transport, $transport_confidence, $connection, $connection_confidence,
                    $classification, $classification_confidence, $classification_provenance,
                    $hardware_ids, $compatible_ids, $raw_json);
                """;
            command.Parameters.AddWithValue("$collected_at_utc", device.CollectedAtUtc.ToString("O"));
            command.Parameters.AddWithValue("$source", device.Source);
            command.Parameters.AddWithValue("$device_instance_id", device.DeviceInstanceId);
            command.Parameters.AddWithValue("$device_type", device.DeviceType);
            command.Parameters.AddWithValue("$vid", device.Vid);
            command.Parameters.AddWithValue("$pid", device.Pid);
            command.Parameters.AddWithValue("$serial", device.Serial);
            command.Parameters.AddWithValue("$friendly_name", device.FriendlyName);
            command.Parameters.AddWithValue("$manufacturer", device.Manufacturer);
            command.Parameters.AddWithValue("$product", device.Product);
            command.Parameters.AddWithValue("$location_information", device.LocationInformation);
            command.Parameters.AddWithValue("$location_paths", device.LocationPaths);
            command.Parameters.AddWithValue("$transport", device.Transport);
            command.Parameters.AddWithValue("$transport_confidence", device.TransportConfidence);
            command.Parameters.AddWithValue("$connection", device.Connection);
            command.Parameters.AddWithValue("$connection_confidence", device.ConnectionConfidence);
            command.Parameters.AddWithValue("$classification", device.Classification);
            command.Parameters.AddWithValue("$classification_confidence", device.ClassificationConfidence);
            command.Parameters.AddWithValue("$classification_provenance", device.ClassificationEvidenceText);
            command.Parameters.AddWithValue("$hardware_ids", device.HardwareIds);
            command.Parameters.AddWithValue("$compatible_ids", device.CompatibleIds);
            command.Parameters.AddWithValue("$raw_json", device.RawJson);
            command.ExecuteNonQuery();
        }

        foreach (var evidence in result.Evidence)
        {
            using var command = connection.CreateCommand();
            command.Transaction = tx;
            command.CommandText = """
                INSERT INTO evidence (
                    timestamp_utc, source, provider, channel, record_id, computer, source_file, source_record,
                    evidence_category, user_explanation, event_id, level, device_hint, summary, raw_text,
                    acquisition_timestamp_utc, source_sha256, provenance)
                VALUES (
                    $timestamp_utc, $source, $provider, $channel, $record_id, $computer, $source_file, $source_record,
                    $evidence_category, $user_explanation, $event_id, $level, $device_hint, $summary, $raw_text,
                    $acquisition_timestamp_utc, $source_sha256, $provenance);
                """;
            command.Parameters.AddWithValue("$timestamp_utc", evidence.TimestampUtc.ToString("O"));
            command.Parameters.AddWithValue("$source", evidence.Source);
            command.Parameters.AddWithValue("$provider", evidence.Provider);
            command.Parameters.AddWithValue("$channel", evidence.Channel);
            command.Parameters.AddWithValue("$record_id", evidence.RecordId.HasValue ? evidence.RecordId.Value : DBNull.Value);
            command.Parameters.AddWithValue("$computer", evidence.Computer);
            command.Parameters.AddWithValue("$source_file", evidence.SourceFile);
            command.Parameters.AddWithValue("$source_record", evidence.SourceRecord);
            command.Parameters.AddWithValue("$evidence_category", evidence.EvidenceCategory);
            command.Parameters.AddWithValue("$user_explanation", evidence.UserExplanation);
            command.Parameters.AddWithValue("$event_id", evidence.EventId);
            command.Parameters.AddWithValue("$level", evidence.Level);
            command.Parameters.AddWithValue("$device_hint", evidence.DeviceHint);
            command.Parameters.AddWithValue("$summary", evidence.Summary);
            command.Parameters.AddWithValue("$raw_text", evidence.RawText);
            command.Parameters.AddWithValue("$acquisition_timestamp_utc", evidence.AcquisitionTimestampUtc.ToString("O"));
            command.Parameters.AddWithValue("$source_sha256", evidence.SourceSha256);
            command.Parameters.AddWithValue("$provenance", evidence.Provenance);
            command.ExecuteNonQuery();
        }

        foreach (var finding in result.CleanupFindings)
        {
            using var command = connection.CreateCommand();
            command.Transaction = tx;
            command.CommandText = """
                INSERT INTO cleanup_findings (timestamp_utc, severity, area, finding, details)
                VALUES ($timestamp_utc, $severity, $area, $finding, $details);
                """;
            command.Parameters.AddWithValue("$timestamp_utc", finding.TimestampUtc.ToString("O"));
            command.Parameters.AddWithValue("$severity", finding.Severity);
            command.Parameters.AddWithValue("$area", finding.Area);
            command.Parameters.AddWithValue("$finding", finding.Finding);
            command.Parameters.AddWithValue("$details", finding.Details);
            command.ExecuteNonQuery();
        }

        tx.Commit();
    }

    private void AppendJsonl(AuditResult result)
    {
        var previousHash = File.Exists(JsonlPath)
            ? File.ReadLines(JsonlPath).LastOrDefault()?.Split("\"recordHash\":\"").LastOrDefault()?.Split('"').FirstOrDefault() ?? ""
            : "";

        using var writer = new StreamWriter(JsonlPath, append: true, Encoding.UTF8);
        foreach (var item in result.Devices.Cast<object>().Concat(result.Evidence).Concat(result.CleanupFindings))
        {
            var payload = JsonSerializer.Serialize(new
            {
                recordType = item.GetType().Name,
                previousHash,
                data = item
            });
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
            var line = JsonSerializer.Serialize(new
            {
                recordType = item.GetType().Name,
                previousHash,
                recordHash = hash,
                data = item
            });
            writer.WriteLine(line);
            previousHash = hash;
        }
    }
}
