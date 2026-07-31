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
/// Безопасный сбор остаточных и offline-артефактов. Реализация не должна изменять
/// исследуемые источники; все загружаемые hive-файлы предварительно копируются.
/// </summary>
public interface IHistoricalArtifactCollector
{
    string ProgressMessage { get; }

    void Collect(AuditResult result, CancellationToken cancellationToken = default);
}

/// <summary>
/// Порт хранилища результатов аудита (SQLite + JSONL).
/// </summary>
public interface IAuditStorage
{
    string DataDirectory { get; }

    string DatabasePath { get; }

    void Save(AuditResult result);

    AuditResult? Load(string sessionId);
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

    /// <summary>
    /// Включает привилегии, нужные для чтения защищённых веток реестра, и
    /// сообщает, что в итоге получилось.
    /// </summary>
    PrivilegeState AcquireAndDescribe() => new(IsAdministrator(), false, false, false);
}

/// <summary>
/// Порт поиска следов развёртывания системы из готового образа.
/// </summary>
public interface IReferenceImageDetector
{
    ReferenceImageTrace Detect(IEnumerable<UsbDeviceRecord> devices, List<string> warnings);
}

/// <summary>
/// Заглушка для сборок без доступа к реестру: проверка просто не выполняется,
/// а отчёт об этом честно сообщает пустым набором признаков.
/// </summary>
public sealed class NoReferenceImageDetector : IReferenceImageDetector
{
    public ReferenceImageTrace Detect(IEnumerable<UsbDeviceRecord> devices, List<string> warnings) => new();
}
