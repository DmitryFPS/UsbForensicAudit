using System.Diagnostics.CodeAnalysis;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace UsbForensicAudit;

/// <summary>
/// ViewModel главного окна: владеет наблюдаемыми коллекциями и состоянием, инкапсулирует запуск
/// сканирования через use case и презентационную логику сортировки/наполнения результатов.
/// Прямая работа с контролами и платформенными API (Win32/буфер обмена/Procmon) остаётся во view.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "WPF ViewModel — живёт только внутри окна приложения")]
public partial class MainViewModel : ObservableObject
{
    private readonly AuditOrchestrator _orchestrator;
    private readonly INetworkEnvironmentService _networkEnvironmentService;

    public MainViewModel(
        AuditOrchestrator orchestrator,
        IReportService reportService,
        INetworkEnvironmentService networkEnvironmentService)
    {
        _orchestrator = orchestrator;
        _networkEnvironmentService = networkEnvironmentService;
        ReportService = reportService;
    }

    public ObservableCollection<UsbDeviceRecord> Devices { get; } = [];

    public ObservableCollection<EvidenceRecord> Evidence { get; } = [];

    public ObservableCollection<CleanupFinding> CleanupFindings { get; } = [];

    public ObservableCollection<NetworkConnectionRecord> NetworkConnections { get; } = [];

    public ObservableCollection<WirelessNetworkRecord> WirelessNetworks { get; } = [];

    public ObservableCollection<NetworkNeighborRecord> NetworkNeighbors { get; } = [];

    /// <summary>История активности устройств, накопленная за сессию из повторных снимков.</summary>
    public ObservableCollection<NetworkNeighborHistory> NetworkNeighborHistory { get; } = [];

    /// <summary>Реальная история подключений самой машины к Wi-Fi из журналов Windows.</summary>
    public ObservableCollection<NetworkConnectionRecord> WiFiConnections { get; } = [];

    public ObservableCollection<NetworkAdapterRecord> NetworkAdapters { get; } = [];

    public ObservableCollection<ExternalUtilityRow> ExternalUtilityRows { get; } = [];

    public ObservableCollection<RunningExternalUtility> RunningExternalUtilities { get; } = [];

    public ObservableCollection<HistoricalUtilityLaunch> HistoricalUtilityLaunches { get; } = [];

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private bool _isProcmonTracing;

    /// <summary>
    /// Сколько в таблице устройств, которые принесли с собой. Без этой строки
    /// приходится считать цветные строки глазами.
    /// </summary>
    [ObservableProperty]
    private string _externalDeviceSummary = "Сканирование ещё не выполнялось.";

    /// <summary>
    /// Сколько нашлось сетевых связей и сколько из них таких, по которым данные
    /// могли уйти с машины. Без этой строки читателю пришлось бы считать строки
    /// таблицы глазами.
    /// </summary>
    [ObservableProperty]
    private string _networkSummary = "Сканирование ещё не выполнялось.";

    /// <summary>Сводка снимка Wi-Fi и соседей по сети.</summary>
    [ObservableProperty]
    private string _networkEnvironmentSummary = "Обстановка вокруг машины не снималась.";

    [ObservableProperty]
    private bool _isCapturingNetworkEnvironment;

    /// <summary>
    /// Показывать в списке соседей только чужие устройства, спрятав сетевую
    /// инфраструктуру: саму машину, шлюз, серверы DHCP и DNS. Инфраструктура
    /// известна заранее и в вопросе «кто ещё в сети» только мешает.
    /// </summary>
    [ObservableProperty]
    private bool _showOnlyDeviceNeighbors = true;

    /// <summary>Последний снимок обстановки — для перефильтрации списка соседей.</summary>
    private NetworkEnvironmentSnapshot? _environmentSnapshot;

    partial void OnShowOnlyDeviceNeighborsChanged(bool value) => RepopulateNeighbors();

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

        NetworkConnections.Clear();
        foreach (var connection in OrderNetworkConnections(result.NetworkConnections))
        {
            NetworkConnections.Add(connection);
        }

        WiFiConnections.Clear();
        foreach (var connection in result.NetworkConnections
                     .Where(x => x.Kind == NetworkConnectionKind.WiFi)
                     .OrderByDescending(x => x.LastSeenUtc ?? DateTimeOffset.MinValue)
                     .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
        {
            WiFiConnections.Add(connection);
        }

        ExternalDeviceSummary = DescribeExternalDevices(result.Devices);
        NetworkSummary = NetworkConnectionSummary.Create(result.NetworkConnections).Describe();
        PopulateNetworkEnvironment(result.NetworkEnvironment);
    }

    public void PopulateNetworkEnvironment(NetworkEnvironmentSnapshot snapshot)
    {
        WirelessNetworks.Clear();
        foreach (var network in snapshot.WirelessNetworks
                     .OrderByDescending(x => x.IsConnected)
                     .ThenByDescending(x => x.HasSavedProfile)
                     .ThenByDescending(x => x.SignalPercent)
                     .ThenBy(x => x.Ssid, StringComparer.OrdinalIgnoreCase))
        {
            WirelessNetworks.Add(network);
        }

        _environmentSnapshot = snapshot;
        RepopulateNeighbors();

        NetworkNeighborHistory.Clear();
        foreach (var history in snapshot.NeighborHistory
                     .OrderByDescending(x => x.LastSeenUtc)
                     .ThenByDescending(x => x.TimesSeen)
                     .ThenBy(x => NeighborRole.Rank(x.Role)))
        {
            NetworkNeighborHistory.Add(history);
        }

        NetworkAdapters.Clear();
        foreach (var adapter in snapshot.Adapters)
        {
            NetworkAdapters.Add(adapter);
        }

        NetworkEnvironmentSummary = snapshot.Describe();
    }

    /// <summary>
    /// Наполняет список соседей с учётом фильтра «Только устройства»:
    /// инфраструктура (эта машина, шлюз, DHCP, DNS) при включённом фильтре
    /// прячется, чтобы не заслонять чужие устройства.
    /// </summary>
    private void RepopulateNeighbors()
    {
        NetworkNeighbors.Clear();
        if (_environmentSnapshot is null)
        {
            return;
        }

        foreach (var neighbor in _environmentSnapshot.Neighbors
                     .Where(x => !ShowOnlyDeviceNeighbors || x.Role == NeighborRole.Neighbor)
                     .OrderBy(x => NeighborRole.Rank(x.Role))
                     .ThenBy(x => x.IpAddress, StringComparer.Ordinal))
        {
            NetworkNeighbors.Add(neighbor);
        }
    }

    public async Task CaptureNetworkEnvironmentAsync(
        bool activeProbe,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        IsCapturingNetworkEnvironment = true;
        try
        {
            var snapshot = await Task.Run(async () =>
                    await _networkEnvironmentService.CaptureAsync(activeProbe, progress, cancellationToken)
                        .ConfigureAwait(false),
                cancellationToken).ConfigureAwait(true);

            // Молчащим устройствам имена достаются из полного аудита машины:
            // телефон, сопряжённый по Bluetooth, известен по аппаратному адресу.
            if (LastResult is not null)
            {
                NeighborAuditEnrichment.Enrich(snapshot.Neighbors, LastResult.Devices);
            }

            // История активности устройств копится по повторным съёмкам за
            // сессию: новый снимок дополняет прежнюю историю, а не стирает её.
            var previousHistory = LastResult?.NetworkEnvironment.NeighborHistory ?? [];
            snapshot.NeighborHistory = NetworkNeighborHistoryAccumulator.Merge(
                previousHistory,
                snapshot.Neighbors,
                snapshot.TakenAtUtc ?? DateTimeOffset.UtcNow);

            if (LastResult is not null)
            {
                LastResult.NetworkEnvironment = snapshot;
                var sessionId = LastResult.SessionId;
                await Task.Run(() => Storage.SaveNetworkEnvironment(sessionId, snapshot), cancellationToken)
                    .ConfigureAwait(true);
            }

            PopulateNetworkEnvironment(snapshot);
        }
        finally
        {
            IsCapturingNetworkEnvironment = false;
        }
    }

    /// <summary>
    /// Сверху то, чем выносят данные и чем управляют чужой машиной, затем сами
    /// сети, и лишь потом сайты: их сотни, и они не должны прятать одну сетевую
    /// папку, куда ушли файлы.
    /// </summary>
    public static IEnumerable<NetworkConnectionRecord> OrderNetworkConnections(
        IEnumerable<NetworkConnectionRecord> connections) =>
        connections
            .OrderBy(x => NetworkConnectionKind.Rank(x.Kind))
            .ThenByDescending(x => x.LastSeenUtc ?? DateTimeOffset.MinValue)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Сводка над таблицей. Считаются устройства, а не строки реестра: иначе
    /// один телефон с полутора десятками услуг Bluetooth выглядит как склад
    /// принесённой техники. Число свёрнутых записей названо отдельно, чтобы
    /// читатель видел, что они никуда не делись.
    /// </summary>
    public static string DescribeExternalDevices(IEnumerable<UsbDeviceRecord> devices)
    {
        var list = devices as IReadOnlyCollection<UsbDeviceRecord> ?? devices.ToList();
        var shown = list.Where(x => !DeviceComposition.IsFoldedByDefault(x)).ToList();
        var media = shown.Count(x => x.Externality == DeviceExternality.ExternalMedia);
        var peripheral = shown.Count(x => x.Externality == DeviceExternality.ExternalPeripheral);
        var possible = shown.Count(x => x.Externality == DeviceExternality.PossiblyExternal);
        var folded = list.Count - shown.Count;
        return $"Принесённых устройств: {media + peripheral} "
               + $"(носителей и телефонов — {media}, прочей внешней периферии — {peripheral}). "
               + $"Ещё {possible} записей на шине USB, где отличить внешнее устройство от встроенного по следам нельзя. "
               + $"Строк в таблице: {shown.Count}. Свёрнуто в них записей реестра: {folded} — "
               + "услуги сопряжённых устройств, грани составных устройств и части шины.";
    }

    /// <summary>
    /// Сверху то, что приносили с собой: носители и телефоны, затем прочая
    /// внешняя периферия. Части шины и следы реестра уходят вниз — читателю
    /// не приходится искать флешку среди корневых концентраторов.
    /// </summary>
    public static IEnumerable<UsbDeviceRecord> OrderDevices(IEnumerable<UsbDeviceRecord> devices) =>
        devices
            .OrderBy(x => DeviceExternality.Rank(x.Externality))
            .ThenBy(x => CategoryRank(x.VisualCategory))
            .ThenBy(x => x.CanonicalDeviceId)
            .ThenByDescending(x => x.IsCanonicalPrimary)
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
        // Делегирует единой шкале в Domain — сортировка в UI, HTML и Excel обязана совпадать.
        return ReportSeverity.Rank(severity);
    }

    public static int CategoryRank(string category)
    {
        return category switch
        {
            "RealUsb" => 0,
            "RelatedStorage" => 1,
            "UsbFlagsTrace" => 2,
            "HistoricalResidual" => 3,
            "SupportArtifact" => 4,
            _ => 5
        };
    }
}
