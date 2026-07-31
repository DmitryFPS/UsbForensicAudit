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
/// Порт чтения изменений файловой системы на внутренних дисках. Нужен только для
/// одного вывода: Windows не журналирует копирование файлов, но журнал изменений
/// NTFS хранит момент появления файла на диске.
///
/// Записи журнала в результат аудита не попадают: их сотни тысяч, и после поиска
/// признаков переноса они не нужны. Сохраняется только глубина журнала и сами
/// найденные признаки.
/// </summary>
public interface IFileSystemChangeCollector
{
    string ProgressMessage { get; }

    bool ShouldRun { get; }

    FileSystemChangeSet Collect(List<string> warnings, CancellationToken cancellationToken = default);
}

/// <summary>
/// Изменения файлов вместе со сведениями о том, за какой период их удалось
/// прочитать. Второе без первого бессмысленно: пустой список изменений без
/// указания глубины журнала читается как «ничего не происходило».
/// </summary>
public sealed record FileSystemChangeSet(
    IReadOnlyList<FileChangeRecord> Changes,
    IReadOnlyList<FileChangeJournalState> Journals)
{
    public static FileSystemChangeSet Empty { get; } = new([], []);
}

/// <summary>
/// Заглушка для сборок без доступа к тому: проверка не выполняется, и отчёт
/// честно сообщает об этом отсутствием сведений о журнале.
/// </summary>
public sealed class NoFileSystemChangeCollector : IFileSystemChangeCollector
{
    public string ProgressMessage => "Чтение журнала изменений не выполняется.";

    public bool ShouldRun => false;

    public FileSystemChangeSet Collect(List<string> warnings, CancellationToken cancellationToken = default) =>
        FileSystemChangeSet.Empty;
}

/// <summary>
/// Порт сборщика сетевых связей: сети Wi-Fi и провод, туннели VPN, пары по
/// Bluetooth, серверы с сетевыми папками, узлы удалённого стола, история
/// браузера. Каждый источник — отдельный сборщик; одна и та же сеть приходит из
/// нескольких сборщиков и сводится в одну связь после сбора.
/// </summary>
public interface INetworkArtifactCollector
{
    string ProgressMessage { get; }

    bool ShouldRun { get; }

    NetworkArtifactSet Collect(List<string> warnings);
}

/// <summary>
/// Найденные связи вместе с записями о полноте источника. Второе без первого
/// обязательно: пустой список сетей без указания состояния журналов читается
/// как «никуда не подключались», хотя журнал мог быть выключен.
/// </summary>
public sealed record NetworkArtifactSet(
    IReadOnlyList<NetworkConnectionRecord> Connections,
    IReadOnlyList<EvidenceRecord> Evidence)
{
    public static NetworkArtifactSet Empty { get; } = new([], []);

    public static NetworkArtifactSet FromConnections(IReadOnlyList<NetworkConnectionRecord> connections) =>
        new(connections, []);
}

/// <summary>
/// Порт хранилища результатов аудита (SQLite + JSONL).
/// </summary>
public interface IAuditStorage
{
    string DataDirectory { get; }

    string DatabasePath { get; }

    void Save(AuditResult result);

    void SaveNetworkEnvironment(string sessionId, NetworkEnvironmentSnapshot snapshot);

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
