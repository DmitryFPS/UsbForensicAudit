using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace UsbForensicAudit;

/// <summary>
/// ViewModel главного окна: владеет наблюдаемыми коллекциями и состоянием, инкапсулирует запуск
/// сканирования через use case и презентационную логику сортировки/наполнения результатов.
/// Прямая работа с контролами и платформенными API (Win32/буфер обмена/Procmon) остаётся во view.
/// </summary>
public partial class MainViewModel : ObservableObject
{
    private readonly AuditOrchestrator _orchestrator;

    public MainViewModel(AuditOrchestrator orchestrator, IReportService reportService)
    {
        _orchestrator = orchestrator;
        ReportService = reportService;
    }

    public ObservableCollection<UsbDeviceRecord> Devices { get; } = [];

    public ObservableCollection<EvidenceRecord> Evidence { get; } = [];

    public ObservableCollection<CleanupFinding> CleanupFindings { get; } = [];

    public ObservableCollection<ExternalUtilityRow> ExternalUtilityRows { get; } = [];

    public ObservableCollection<RunningExternalUtility> RunningExternalUtilities { get; } = [];

    public ObservableCollection<HistoricalUtilityLaunch> HistoricalUtilityLaunches { get; } = [];

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private bool _isProcmonTracing;

    public AuditResult? LastResult { get; set; }

    public IReportService ReportService { get; }

    public IAuditStorage Storage => _orchestrator.Storage;

    public Task<AuditResult> RunFullScanAsync(IProgress<string>? progress = null, CancellationToken cancellationToken = default) =>
        _orchestrator.RunFullScanAsync(progress, cancellationToken);

    /// <summary>
    /// Наполняет наблюдаемые коллекции результатами аудита в порядке отображения:
    /// устройства — по категории и имени, доказательства — от новых к старым,
    /// признаки очистки — сначала подозрительные и более серьёзные.
    /// </summary>
    public void PopulateFromResult(AuditResult result)
    {
        Devices.Clear();
        foreach (var device in OrderDevices(result.Devices))
        {
            Devices.Add(device);
        }

        Evidence.Clear();
        foreach (var evidence in OrderEvidence(result.Evidence))
        {
            Evidence.Add(evidence);
        }

        CleanupFindings.Clear();
        foreach (var finding in OrderCleanupFindings(result.CleanupFindings))
        {
            CleanupFindings.Add(finding);
        }
    }

    public static IEnumerable<UsbDeviceRecord> OrderDevices(IEnumerable<UsbDeviceRecord> devices) =>
        devices
            .OrderBy(x => CategoryRank(x.VisualCategory))
            .ThenBy(x => x.DisplayName);

    public static IEnumerable<EvidenceRecord> OrderEvidence(IEnumerable<EvidenceRecord> evidence) =>
        evidence.OrderByDescending(x => x.TimestampUtc);

    public static IEnumerable<CleanupFinding> OrderCleanupFindings(IEnumerable<CleanupFinding> findings) =>
        findings
            .OrderByDescending(x => x.IsSuspicious)
            .ThenByDescending(x => SeverityRank(x.Severity))
            .ThenByDescending(x => x.TimestampUtc);

    public static int SeverityRank(string severity)
    {
        return severity.ToLowerInvariant() switch
        {
            "critical" => 5,
            "high" => 4,
            "medium" => 3,
            "low" => 2,
            "info" => 1,
            _ => 0
        };
    }

    public static int CategoryRank(string category)
    {
        return category switch
        {
            "RealUsb" => 0,
            "RelatedStorage" => 1,
            "SupportArtifact" => 2,
            _ => 3
        };
    }
}
