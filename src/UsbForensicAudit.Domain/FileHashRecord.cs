namespace UsbForensicAudit;

/// <summary>Результат хеширования одного файла, запускавшегося со съёмного носителя.</summary>
public enum FileHashStatus
{
    /// <summary>Файл найден и хеш посчитан.</summary>
    Hashed,

    /// <summary>Файла уже нет на диске (типично для запусков с давно вынутой флешки).</summary>
    NotFound,

    /// <summary>Файл есть, но прочитать не удалось (нет прав, занят и т.п.).</summary>
    Error
}

/// <summary>
/// Хеш исполняемого файла, чьи следы запуска (Prefetch/Amcache) указывают на
/// съёмный носитель. Позволяет сверить, что именно запускали, с известными
/// образцами — без выхода в сеть по умолчанию.
/// </summary>
public sealed class FileHashRecord
{
    public required string Path { get; init; }
    public required FileHashStatus Status { get; init; }
    public string? Sha256 { get; init; }
    public long? SizeBytes { get; init; }
    public string? Error { get; init; }

    public string StatusText => Status switch
    {
        FileHashStatus.Hashed => "Хеш посчитан",
        FileHashStatus.NotFound => "Файл не найден (носитель, вероятно, извлечён)",
        _ => "Не удалось прочитать файл"
    };

    public static FileHashRecord NotFoundAt(string path) => new() { Path = path, Status = FileHashStatus.NotFound };
    public static FileHashRecord Failed(string path, string error) => new() { Path = path, Status = FileHashStatus.Error, Error = error };
    public static FileHashRecord Ok(string path, string sha256, long size) =>
        new() { Path = path, Status = FileHashStatus.Hashed, Sha256 = sha256, SizeBytes = size };
}
