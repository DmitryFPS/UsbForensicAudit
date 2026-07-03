namespace UsbForensicAudit;

public sealed class AuditOrchestrator
{
    private readonly UsbRegistryCollector _registryCollector = new();
    private readonly SetupApiLogCollector _setupApiLogCollector = new();
    private readonly EventLogCollector _eventLogCollector = new();
    private readonly EndpointProtectionEventLogCollector _endpointProtectionEventLogCollector = new();
    private readonly UserArtifactCollector _userArtifactCollector = new();
    private readonly OfflineHiveCollector _offlineHiveCollector = new();
    private readonly ExecutionArtifactCollector _executionArtifactCollector = new();
    private readonly ProcessAttributionCollector _processAttributionCollector = new();
    private readonly CorrelationService _correlationService = new();
    private readonly TimelineEnricher _timelineEnricher = new(new WmiConnectedDeviceProbe());
    private readonly LiveDeviceMerger _liveDeviceMerger = new();
    private readonly CleanupDetector _cleanupDetector = new();
    private readonly AuditStorage _storage = new();

    public AuditStorage Storage => _storage;

    public async Task<AuditResult> RunFullScanAsync(IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            var result = new AuditResult
            {
                StartedAtUtc = DateTimeOffset.UtcNow,
                OsInstalledAtUtc = OsInstallInfo.GetInstalledAtUtc(),
                IsAdministrator = AdminHelper.IsAdministrator()
            };

            progress?.Report("Чтение Registry USB/USBSTOR/SCSI/WPD...");
            result.Devices.AddRange(_registryCollector.Collect(result.SourceWarnings));
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Парсинг setupapi.dev.log...");
            result.Evidence.AddRange(_setupApiLogCollector.Collect(result.SourceWarnings));
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Чтение Windows Event Logs...");
            result.Evidence.AddRange(_eventLogCollector.Collect(result.SourceWarnings));
            cancellationToken.ThrowIfCancellationRequested();

            if (EndpointProtectionEnvironment.IsInstalled)
            {
                progress?.Report("Чтение журнала корпоративной защиты USB...");
                result.Evidence.AddRange(_endpointProtectionEventLogCollector.Collect(result.SourceWarnings));
            }

            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Сбор пользовательских артефактов: HKU, Recent, LNK, Jump Lists...");
            result.Evidence.AddRange(_userArtifactCollector.Collect(result.SourceWarnings));
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Offline-анализ NTUSER.DAT и UsrClass.dat...");
            result.Evidence.AddRange(_offlineHiveCollector.Collect(result.SourceWarnings));
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Сбор артефактов запуска: Prefetch, Amcache, Shimcache...");
            result.Evidence.AddRange(_executionArtifactCollector.Collect(result.SourceWarnings));
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Поиск процессов очистки в Security (4688)...");
            result.Evidence.AddRange(_processAttributionCollector.Collect(result.SourceWarnings));
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Корреляция device -> evidence -> user artifacts...");
            result.Evidence.AddRange(_correlationService.BuildDeviceCorrelations(result));
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Сопоставление с устройствами, подключёнными прямо сейчас...");
            _liveDeviceMerger.Merge(result);
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
