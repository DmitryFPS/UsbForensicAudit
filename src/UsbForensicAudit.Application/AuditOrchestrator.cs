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
    private readonly IHistoricalArtifactCollector _historicalArtifactCollector;
    private readonly CorrelationService _correlationService;
    private readonly ILiveDeviceMerger _liveDeviceMerger;
    private readonly TimelineEnricher _timelineEnricher;
    private readonly CleanupDetector _cleanupDetector;
    private readonly IAuditStorage _storage;
    private readonly IPrivilegeChecker _privilegeChecker;

    public AuditOrchestrator(
        IUsbDeviceCollector deviceCollector,
        IEnumerable<IEvidenceCollector> evidenceCollectors,
        IHistoricalArtifactCollector historicalArtifactCollector,
        CorrelationService correlationService,
        ILiveDeviceMerger liveDeviceMerger,
        TimelineEnricher timelineEnricher,
        CleanupDetector cleanupDetector,
        IAuditStorage storage,
        IPrivilegeChecker privilegeChecker)
    {
        _deviceCollector = deviceCollector;
        _evidenceCollectors = evidenceCollectors.ToList();
        _historicalArtifactCollector = historicalArtifactCollector;
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
            var warningCount = result.SourceWarnings.Count;
            var devices = _deviceCollector.Collect(result.SourceWarnings);
            result.Devices.AddRange(devices);
            AddCoverage(result, _deviceCollector.GetType().Name, devices.Count, warningCount);
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var collector in _evidenceCollectors)
            {
                if (!collector.ShouldRun)
                {
                    result.Coverage.Sources.Add(new SourceCoverage
                    {
                        Source = collector.GetType().Name,
                        Status = "NotRun"
                    });
                    continue;
                }

                progress?.Report(collector.ProgressMessage);
                warningCount = result.SourceWarnings.Count;
                var collected = collector.Collect(result.SourceWarnings);
                result.Evidence.AddRange(collected);
                AddCoverage(result, collector.GetType().Name, collected.Count, warningCount);
                cancellationToken.ThrowIfCancellationRequested();
            }

            DeduplicateUserArtifacts(result.Evidence);

            progress?.Report(_historicalArtifactCollector.ProgressMessage);
            var historicalEvidenceBefore = result.Evidence.Count;
            warningCount = result.SourceWarnings.Count;
            _historicalArtifactCollector.Collect(result, cancellationToken);
            AddCoverage(result, _historicalArtifactCollector.GetType().Name,
                result.Evidence.Count - historicalEvidenceBefore, warningCount);
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Сопоставление с устройствами, подключёнными прямо сейчас...");
            _liveDeviceMerger.Merge(result);
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Корреляция physical device -> volumes -> user artifacts...");
            DeviceTransportClassifier.ClassifyAll(result.Devices);
            DeviceIdentityGraph.Process(result.Devices);
            VolumeCorrelationService.Process(result);
            result.Evidence.AddRange(_correlationService.BuildDeviceCorrelations(result));
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report("Расчет дат подключения/отключения и пояснений...");
            _timelineEnricher.Enrich(result);
            CalculateDateCoverage(result);
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

    internal static void AddCoverage(AuditResult result, string source, int count, int warningCountBefore)
    {
        var newWarnings = result.SourceWarnings.Skip(warningCountBefore).ToArray();
        var limit = newWarnings
            .Select(x => System.Text.RegularExpressions.Regex.Match(
                x, @"(?:лимит|limit)\D*(\d[\d\s]*)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            .Where(x => x.Success)
            .Select(x => int.TryParse(x.Groups[1].Value.Replace(" ", ""), out var value) ? value : 0)
            .FirstOrDefault(x => x > 0);
        result.Coverage.Sources.Add(new SourceCoverage
        {
            Source = source,
            Count = count,
            Status = newWarnings.Length == 0 ? "Complete" : count > 0 ? "Partial" : "Error",
            Capped = newWarnings.Any(x => x.Contains("лимит", StringComparison.OrdinalIgnoreCase)
                                          || x.Contains("limit", StringComparison.OrdinalIgnoreCase)),
            Error = string.Join("; ", newWarnings),
            Limit = limit
        });
    }

    private static void DeduplicateUserArtifacts(List<EvidenceRecord> evidence)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < evidence.Count;)
        {
            var item = evidence[i];
            if (string.IsNullOrWhiteSpace(item.UserSid))
            {
                i++;
                continue;
            }
            var source = item.Source
                .Replace("Offline NTUSER.DAT ", "", StringComparison.OrdinalIgnoreCase)
                .Replace("Offline UsrClass.dat ", "", StringComparison.OrdinalIgnoreCase)
                .Replace("Live HKU SID_Classes ", "", StringComparison.OrdinalIgnoreCase)
                .Trim();
            var key = string.Join("|",
                item.UserSid.Trim().ToUpperInvariant(),
                source.ToUpperInvariant(),
                item.DeviceHint.Trim().ToUpperInvariant(),
                item.SourceRecord.Split('\\').LastOrDefault()?.ToUpperInvariant() ?? "");
            if (seen.Add(key))
            {
                i++;
            }
            else
            {
                evidence.RemoveAt(i);
            }
        }
    }

    internal static void CalculateDateCoverage(AuditResult result)
    {
        var canonical = result.Devices
            .Where(x => x.IsCanonicalPrimary || (!string.IsNullOrWhiteSpace(x.CanonicalDeviceId)
                                                  && result.Devices.Count(y => y.CanonicalDeviceId.Equals(
                                                      x.CanonicalDeviceId, StringComparison.OrdinalIgnoreCase)) == 1))
            .ToArray();
        result.Coverage.CanonicalDeviceCount = canonical.Length;
        result.Coverage.CanonicalDevicesWithExactDates = canonical.Count(x =>
            x.FirstConnectedUtc.HasValue
            && (x.ConnectionDisplayKind.Equals("ExactEvent", StringComparison.OrdinalIgnoreCase)
                || x.ConnectionDisplayKind.Equals("PnpDevProperty", StringComparison.OrdinalIgnoreCase)));
    }
}
