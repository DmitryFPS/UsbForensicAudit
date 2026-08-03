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

        // Имена внутри архива должны быть уникальны: два файла с одинаковым
        // именем из разных папок иначе молча затёрли бы друг друга в ZIP, и
        // одно доказательство пропало бы незаметно.
        var usedEntryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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

                    var entryName = UniqueEntryName(Path.GetFileName(file), usedEntryNames);
                    // Не CreateEntryFromFile: базу audit.sqlite держит открытой сам
                    // процесс (пул соединений), поэтому читаем с FileShare.ReadWrite.
                    // Хеш считается в том же проходе, что и копирование: манифест
                    // описывает ровно те байты, которые легли в архив.
                    var entry = archive.CreateEntry(entryName);
                    entry.LastWriteTime = File.GetLastWriteTime(file);
                    string sha256;
                    long sizeBytes;
                    using (var source = OpenShared(file))
                    using (var target = entry.Open())
                    {
                        (sha256, sizeBytes) = CopyAndHash(source, target);
                    }

                    included.Add(file);
                    manifestEntries.Add(new ManifestEntry
                    {
                        File = entryName,
                        Sha256 = sha256,
                        SizeBytes = sizeBytes
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

    /// <summary>
    /// Гарантирует уникальность имени в архиве: при коллизии добавляет « (2)»,
    /// « (3)» и т.д. перед расширением. Так ни один доказательный файл не
    /// затирается другим с тем же именем из другой папки.
    /// </summary>
    private static string UniqueEntryName(string name, HashSet<string> used)
    {
        if (used.Add(name))
        {
            return name;
        }

        var stem = Path.GetFileNameWithoutExtension(name);
        var ext = Path.GetExtension(name);
        for (var i = 2; ; i++)
        {
            var candidate = $"{stem} ({i}){ext}";
            if (used.Add(candidate))
            {
                return candidate;
            }
        }
    }

    private static (string Sha256, long SizeBytes) CopyAndHash(Stream source, Stream target)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            target.Write(buffer, 0, read);
            sha.AppendData(buffer, 0, read);
            total += read;
        }

        return (Convert.ToHexString(sha.GetHashAndReset()), total);
    }

    /// <summary>Чтение, не конфликтующее с файлами, открытыми процессом на запись.</summary>
    private static FileStream OpenShared(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

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
