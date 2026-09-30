using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace UsbForensicAudit;

public sealed partial class AuditStorage
{
    /// <summary>Удаляет карточки текущего сканирования из рабочей базы. Исходный журнал доказательств — архив.</summary>
    public DatabaseDeviceRemovalResult DeleteDeviceRecords(string sessionId, IReadOnlyCollection<string> instanceIds)
    {
        if (string.IsNullOrWhiteSpace(sessionId) || instanceIds.Count == 0 || instanceIds.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("Выберите записи сохранённого сканирования.");
        }

        DatabaseDeviceRemovalResult result = new(0, "");
        ExecuteExclusive(() =>
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction();
            var selected = instanceIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var rows = new List<(long Id, string Json)>();
            using (var read = connection.CreateCommand())
            {
                read.Transaction = transaction;
                read.CommandText = "SELECT id, device_instance_id, record_json FROM devices WHERE session_id=$session;";
                read.Parameters.AddWithValue("$session", sessionId);
                using var reader = read.ExecuteReader();
                while (reader.Read())
                {
                    if (selected.Contains(reader.GetString(1)))
                    {
                        rows.Add((reader.GetInt64(0), reader.GetString(2)));
                    }
                }
            }
            if (rows.Count == 0)
            {
                return;
            }

            var cacheAddresses = selected.Select(BluetoothCacheIdentity.AddressFromPath).Where(x => x.Length > 0).ToHashSet();
            var networkRows = new List<(long Id, string Json)>();
            if (cacheAddresses.Count > 0)
            {
                using var readNetwork = connection.CreateCommand();
                readNetwork.Transaction = transaction;
                readNetwork.CommandText = "SELECT id, record_json FROM network_connections WHERE session_id=$session;";
                readNetwork.Parameters.AddWithValue("$session", sessionId);
                using var reader = readNetwork.ExecuteReader();
                while (reader.Read())
                {
                    var json = reader.GetString(1);
                    var record = JsonSerializer.Deserialize<NetworkConnectionRecord>(json, JsonOptions);
                    if (record?.Kind == NetworkConnectionKind.Bluetooth
                        && cacheAddresses.Contains(BluetoothCacheIdentity.AddressFromPath(record.Provenance)))
                    {
                        networkRows.Add((reader.GetInt64(0), json));
                    }
                }
            }

            var backup = Path.Combine(DataDirectory, "database-removal", $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}");
            Directory.CreateDirectory(backup);
            var file = Path.Combine(backup, "devices.json");
            File.WriteAllText(file, JsonSerializer.Serialize(new
            {
                SessionId = sessionId,
                Records = rows.Select(x => JsonSerializer.Deserialize<JsonElement>(x.Json)),
                NetworkRecords = networkRows.Select(x => JsonSerializer.Deserialize<JsonElement>(x.Json)),
                Note = "Удаление карточек из рабочей базы. Архив evidence.jsonl, события и готовые отчёты сохраняются."
            }));
            using (var stream = File.OpenRead(file))
            {
                File.WriteAllText(Path.Combine(backup, "sha256.txt"), Convert.ToHexString(SHA256.HashData(stream)));
            }

            foreach (var row in rows)
            {
                using var delete = connection.CreateCommand();
                delete.Transaction = transaction;
                delete.CommandText = "DELETE FROM devices WHERE id=$id AND session_id=$session;";
                delete.Parameters.AddWithValue("$id", row.Id);
                delete.Parameters.AddWithValue("$session", sessionId);
                if (delete.ExecuteNonQuery() != 1)
                {
                    throw new IOException("Список записей изменился. Удаление отменено.");
                }
            }
            foreach (var row in networkRows)
            {
                using var delete = connection.CreateCommand();
                delete.Transaction = transaction;
                delete.CommandText = "DELETE FROM network_connections WHERE id=$id AND session_id=$session;";
                delete.Parameters.AddWithValue("$id", row.Id);
                delete.Parameters.AddWithValue("$session", sessionId);
                if (delete.ExecuteNonQuery() != 1) { throw new IOException("Сетевые записи изменились. Удаление отменено."); }
            }
            transaction.Commit();
            result = new(rows.Count, backup, networkRows.Count);
        });
        return result;
    }
}
