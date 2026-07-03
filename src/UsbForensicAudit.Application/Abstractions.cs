namespace UsbForensicAudit;

/// <summary>
/// Порт сборщика USB-устройств (первый шаг конвейера сканирования).
/// </summary>
public interface IUsbDeviceCollector
{
    string ProgressMessage { get; }

    IReadOnlyList<UsbDeviceRecord> Collect(List<string> warnings);
}

/// <summary>
/// Порт сборщика доказательств. Каждый источник — отдельный сборщик; порядок и текст прогресса
/// задаёт сам сборщик, что позволяет добавлять новые источники без правки оркестратора.
/// </summary>
public interface IEvidenceCollector
{
    string ProgressMessage { get; }

    bool ShouldRun { get; }

    IReadOnlyList<EvidenceRecord> Collect(List<string> warnings);
}

/// <summary>
/// Порт хранилища результатов аудита (SQLite + JSONL).
/// </summary>
public interface IAuditStorage
{
    string DataDirectory { get; }

    string DatabasePath { get; }

    void Save(AuditResult result);
}

/// <summary>
/// Порт слияния результата сканирования с устройствами, подключёнными в момент аудита.
/// </summary>
public interface ILiveDeviceMerger
{
    void Merge(AuditResult result);
}

/// <summary>
/// Порт проверки прав администратора.
/// </summary>
public interface IPrivilegeChecker
{
    bool IsAdministrator();
}
