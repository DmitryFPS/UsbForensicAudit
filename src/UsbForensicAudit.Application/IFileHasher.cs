namespace UsbForensicAudit;

/// <summary>
/// Порт хеширования файла по пути. Реализация читает файл (инфраструктура);
/// Application зависит только от абстракции, поэтому логику сбора хешей можно
/// тестировать без реальной файловой системы.
/// </summary>
public interface IFileHasher
{
    FileHashRecord Hash(string path);
}
