namespace UsbForensicAudit;

/// <summary>
/// Use case полного forensic-сканирования: последовательно запускает сборщик устройств и
/// конвейер сборщиков доказательств, затем аналитические шаги (корреляция, слияние с live,
/// таймлайн, поиск очистки) и сохраняет результат. Зависит только от портов слоя Application.
/// </summary>
public sealed class AuditOrchestrator
{
    private readonly IUsbDeviceCollector _deviceCollector;
    private readonly IReadOnlyList<IEvidenceCollector> _evidenceCollectors;
    private readonly CorrelationService _correlationService;
    private readonly ILiveDeviceMerger _liveDeviceMerger;
    private readonly TimelineEnricher _timelineEnricher;
    private readonly CleanupDetector _cleanupDetector;
    private readonly IAuditStorage _storage;
    private readonly IPrivilegeChecker _privilegeChecker;

    public AuditOrchestrator(
        IUsbDeviceCollector deviceCollector,
        IEnumerable<IEvidenceCollector> evidenceCollectors,
        CorrelationService correlationService,
        ILiveDeviceMerger liveDeviceMerger,
        TimelineEnricher timelineEnricher,
        CleanupDetector cleanupDetector,
        IAuditStorage storage,
        IPrivilegeChecker privilegeChecker)
    {
        _deviceCollector = deviceCollector;
        _evidenceCollectors = evidenceCollectors.ToList();
        _correlationService = correlationService;
        _liveDeviceMerger = liveDeviceMerger;
        _timelineEnricher = timelineEnricher;
        _cleanupDetector = cleanupDetector;
        _storage = storage;
        _privilegeChecker = privilegeChecker;
    }

    public IAuditStorage Storage => _storage;

    public async Task<AuditResult> RunFullScanAsync(IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            var result = new AuditResult
            {
                StartedAtUtc = DateTimeOffset.UtcNow,
                OsInstalledAtUtc = OsInstallInfo.GetInstalledAtUtc(),
                IsAdministrator = _privilegeChecker.IsAdministrator()
            };

            progress?.Report(_deviceCollector.ProgressMessage);
            result.Devices.AddRange(_deviceCollector.Collect(result.SourceWarnings));
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var collector in _evidenceCollectors)
            {
                if (!collector.ShouldRun)
                {
                    continue;
                }

                progress?.Report(collector.ProgressMessage);
                result.Evidence.AddRange(collector.Collect(result.SourceWarnings));
                cancellationToken.ThrowIfCancellationRequested();
            }

            progress?.Report("Сопоставление с устройствами, подключёнными прямо сейчас...");
            _liveDeviceMerger.Merge(result);
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Корреляция physical device -> volumes -> user artifacts...");
            DeviceIdentityGraph.Process(result.Devices);
            VolumeCorrelationService.Process(result);
            result.Evidence.AddRange(_correlationService.BuildDeviceCorrelations(result));
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Расчет дат подключения/отключения и пояснений...");
            _timelineEnricher.Enrich(result);
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Поиск признаков очистки...");
            result.CleanupFindings.AddRange(_cleanupDetector.Analyze(result));

            result.FinishedAtUtc = DateTimeOffset.UtcNow;

            progress?.Report("Сохранение SQLite/JSONL...");
            _storage.Save(result);
            progress?.Report("Сканирование завершено.");

            return result;
        }, cancellationToken);
    }
}
