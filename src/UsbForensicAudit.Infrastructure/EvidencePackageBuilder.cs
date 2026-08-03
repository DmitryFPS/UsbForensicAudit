using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace UsbForensicAudit;

/// <summary>Итог сборки пакета доказательств: путь к архиву и перечень включённого.</summary>
public sealed class EvidencePackageResult
{
    public required string ArchivePath { get; init; }
    public required IReadOnlyList<string> IncludedFiles { get; init; }
    public required IReadOnlyList<string> MissingFiles { get; init; }
}

/// <summary>
/// Собирает передаваемый пакет доказательств: отчёты, сырьё (база сессий и
/// журнал evidence.jsonl) и манифест с SHA-256 каждого файла, версией программы,
/// оператором и временем. Манифест делает пакет самопроверяемым: получатель
/// пересчитывает хеши и убеждается, что ничего не подменено. Опирается на уже
/// существующую печать целостности сессий (seal_hash / evidence.jsonl).
/// </summary>
public static class EvidencePackageBuilder
{
    public static EvidencePackageResult Build(
        string archivePath,
        IEnumerable<string> files,
        string? examiner = null,
        string? caseNumber = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);

        var included = new List<string>();
        var missing = new List<string>();
        var manifestEntries = new List<ManifestEntry>();

        var directory = Path.GetDirectoryName(Path.GetFullPath(archivePath));
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // Пишем во временный файл и переименовываем: незавершённый архив не
        // должен выглядеть готовым пакетом, если сборка прервётся.
        var temporaryPath = archivePath + "." + Guid.NewGuid().ToString("N") + ".tmp";

        try
        {
            using (var zipStream = new FileStream(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create))
            {
                foreach (var file in files.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    if (!File.Exists(file))
                    {
                        missing.Add(file);
                        continue;
                    }

                    var entryName = Path.GetFileName(file);
                    archive.CreateEntryFromFile(file, entryName);
                    included.Add(file);
                    manifestEntries.Add(new ManifestEntry
                    {
                        File = entryName,
                        Sha256 = ComputeSha256(file),
                        SizeBytes = new FileInfo(file).Length
                    });
                }

                var manifest = new PackageManifest
                {
                    Tool = "UsbForensicAudit",
                    CreatedAtUtc = DateTimeOffset.UtcNow,
                    Examiner = examiner,
                    CaseNumber = caseNumber,
                    Files = manifestEntries
                };

                var manifestEntry = archive.CreateEntry("manifest.json");
                using var manifestStream = manifestEntry.Open();
                using var writer = new StreamWriter(manifestStream, new UTF8Encoding(false));
                writer.Write(JsonSerializer.Serialize(manifest, ManifestJsonOptions));
            }

            File.Move(temporaryPath, archivePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }

        return new EvidencePackageResult
        {
            ArchivePath = archivePath,
            IncludedFiles = included,
            MissingFiles = missing
        };
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private sealed class PackageManifest
    {
        public required string Tool { get; init; }
        public required DateTimeOffset CreatedAtUtc { get; init; }
        public string? Examiner { get; init; }
        public string? CaseNumber { get; init; }
        public required IReadOnlyList<ManifestEntry> Files { get; init; }
    }

    private sealed class ManifestEntry
    {
        public required string File { get; init; }
        public required string Sha256 { get; init; }
        public required long SizeBytes { get; init; }
    }
}
