namespace UsbForensicAudit;

/// <summary>
/// Краткая карточка сохранённой сессии сканирования — то, что нужно, чтобы
/// выбрать сессии для сравнения, не загружая их целиком.
/// </summary>
public sealed class SessionSummary
{
    public string SessionId { get; set; } = "";
    public DateTimeOffset StartedAtUtc { get; set; }
    public DateTimeOffset FinishedAtUtc { get; set; }
    public string ComputerName { get; set; } = "";
    public string UserName { get; set; } = "";
    public int DeviceCount { get; set; }
    public int EvidenceCount { get; set; }
    public int CleanupFindingCount { get; set; }
    public int NetworkConnectionCount { get; set; }
}

/// <summary>
/// Результат сравнения двух сессий сканирования: что появилось и что исчезло
/// между базовой (старой) и целевой (новой) сессиями.
/// </summary>
public sealed class SessionDiffReport
{
    public SessionSummary Baseline { get; set; } = new();
    public SessionSummary Target { get; set; } = new();

    /// <summary>Устройства, которых не было в базовой сессии.</summary>
    public List<UsbDeviceRecord> AddedDevices { get; } = [];

    /// <summary>Устройства из базовой сессии, отсутствующие в целевой.</summary>
    public List<UsbDeviceRecord> RemovedDevices { get; } = [];

    /// <summary>Новые доказательства, появившиеся в целевой сессии.</summary>
    public List<EvidenceRecord> AddedEvidence { get; } = [];

    /// <summary>
    /// Доказательства из базовой сессии, которые целевая больше не видит.
    /// Для forensic-анализа это самый тревожный список: артефакты не должны
    /// исчезать сами по себе — их исчезновение указывает на очистку следов
    /// либо на ротацию/усечение журналов.
    /// </summary>
    public List<EvidenceRecord> MissingEvidence { get; } = [];

    /// <summary>Новые признаки очистки следов.</summary>
    public List<CleanupFinding> AddedCleanupFindings { get; } = [];

    /// <summary>Новые сетевые связи.</summary>
    public List<NetworkConnectionRecord> AddedNetworkConnections { get; } = [];

    /// <summary>Сетевые связи, исчезнувшие из целевой сессии.</summary>
    public List<NetworkConnectionRecord> RemovedNetworkConnections { get; } = [];

    public bool HasChanges =>
        AddedDevices.Count > 0 || RemovedDevices.Count > 0 ||
        AddedEvidence.Count > 0 || MissingEvidence.Count > 0 ||
        AddedCleanupFindings.Count > 0 ||
        AddedNetworkConnections.Count > 0 || RemovedNetworkConnections.Count > 0;
}

/// <summary>
/// Сравнение двух сохранённых сессий сканирования. Ключи сопоставления выбраны
/// стабильными между запусками: канонический идентификатор устройства, а не
/// порядок обнаружения; содержательные поля доказательства, а не автоинкрементный
/// id строки. Время самого сканирования в ключи не входит — иначе каждая сессия
/// отличалась бы от любой другой целиком.
/// </summary>
public static class SessionDiffService
{
    public static SessionDiffReport Compare(AuditResult baseline, AuditResult target)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(target);

        var report = new SessionDiffReport
        {
            Baseline = Summarize(baseline),
            Target = Summarize(target)
        };

        DiffInto(
            baseline.Devices, target.Devices, DeviceKey,
            report.AddedDevices, report.RemovedDevices);
        DiffInto(
            baseline.Evidence, target.Evidence, EvidenceKey,
            report.AddedEvidence, report.MissingEvidence);
        DiffInto(
            baseline.NetworkConnections, target.NetworkConnections, NetworkKey,
            report.AddedNetworkConnections, report.RemovedNetworkConnections);

        // Признаки очистки сравниваем только в одну сторону: их «исчезновение»
        // между сессиями не имеет смысла — важно лишь то, что появилось нового.
        var baselineFindings = baseline.CleanupFindings.Select(CleanupKey).ToHashSet(StringComparer.Ordinal);
        report.AddedCleanupFindings.AddRange(
            target.CleanupFindings.Where(f => !baselineFindings.Contains(CleanupKey(f))));

        return report;
    }

    public static SessionSummary Summarize(AuditResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return new SessionSummary
        {
            SessionId = result.SessionId,
            StartedAtUtc = result.StartedAtUtc,
            FinishedAtUtc = result.FinishedAtUtc,
            ComputerName = result.ComputerName,
            UserName = result.UserName,
            DeviceCount = result.Devices.Count,
            EvidenceCount = result.Evidence.Count,
            CleanupFindingCount = result.CleanupFindings.Count,
            NetworkConnectionCount = result.NetworkConnections.Count
        };
    }

    private static void DiffInto<T>(
        IReadOnlyList<T> baseline,
        IReadOnlyList<T> target,
        Func<T, string> key,
        List<T> added,
        List<T> removed)
    {
        var baselineKeys = baseline.Select(key).ToHashSet(StringComparer.Ordinal);
        var targetKeys = target.Select(key).ToHashSet(StringComparer.Ordinal);
        added.AddRange(target.Where(item => !baselineKeys.Contains(key(item))));
        removed.AddRange(baseline.Where(item => !targetKeys.Contains(key(item))));
    }

    private static string DeviceKey(UsbDeviceRecord device) =>
        !string.IsNullOrWhiteSpace(device.CanonicalDeviceId)
            ? $"canonical|{device.CanonicalDeviceId}"
            : $"instance|{device.Source}|{device.DeviceInstanceId}";

    private static string EvidenceKey(EvidenceRecord evidence) =>
        string.Join('|',
            evidence.Source, evidence.Provider, evidence.Channel,
            evidence.EventId, evidence.RecordId?.ToString() ?? "",
            evidence.TimestampUtc.ToString("O"), evidence.DeviceHint, evidence.Summary);

    private static string NetworkKey(NetworkConnectionRecord connection) =>
        !string.IsNullOrWhiteSpace(connection.CanonicalKey)
            ? $"canonical|{connection.CanonicalKey}"
            : $"triple|{connection.Kind}|{connection.Name}|{connection.Address}";

    private static string CleanupKey(CleanupFinding finding) =>
        string.Join('|',
            finding.TimestampUtc.ToString("O"), finding.Severity,
            finding.Area, finding.Finding);
}
