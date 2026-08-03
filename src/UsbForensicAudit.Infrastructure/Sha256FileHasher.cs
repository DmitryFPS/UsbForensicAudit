using System.IO;
using System.Security.Cryptography;

namespace UsbForensicAudit;

/// <summary>
/// Инфраструктурная реализация <see cref="IFileHasher"/>: считает SHA-256 файла
/// потоково (без загрузки целиком в память). Отсутствие файла и ошибки чтения
/// возвращаются как статус записи, а не исключением — сбор хешей не должен
/// прерываться из-за одного недоступного файла.
/// </summary>
public sealed class Sha256FileHasher : IFileHasher
{
    public FileHashRecord Hash(string path)
    {
        if (!File.Exists(path))
        {
            return FileHashRecord.NotFoundAt(path);
        }

        try
        {
            using var stream = File.OpenRead(path);
            var hash = Convert.ToHexString(SHA256.HashData(stream));
            return FileHashRecord.Ok(path, hash, new FileInfo(path).Length);
        }
        catch (Exception exception)
        {
            return FileHashRecord.Failed(path, exception.Message);
        }
    }
}
