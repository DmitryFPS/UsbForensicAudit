using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;

namespace UsbForensicAudit;

/// <summary>
/// Headless-запуск полного forensic-сканирования поверх того же конвейера
/// <see cref="AuditOrchestrator"/>, что и GUI. Результат сохраняется в то же
/// хранилище (SQLite + JSONL с hash-chain), дополнительно доступны экспорт в
/// JSON и генерация отчётов без открытия окна. Все пользовательские сообщения
/// берутся из ресурсов <see cref="CliStrings"/> (ru — базовая культура, en —
/// satellite): язык выбирается системой или флагом --lang.
/// </summary>
internal static class Program
{
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitNotAdministrator = 2;
    private const int ExitCancelled = 3;

    /// <summary>Верификация нашла разрывы hash-chain или расхождения печатей.</summary>
    private const int ExitIntegrityViolation = 4;

    private const int ExitUsage = 64;

    private static async Task<int> Main(string[] args)
    {
        var options = CliOptions.Parse(args);
        if (options.ShowHelp)
        {
            Console.WriteLine(CliStrings.Get("Usage"));
            return ExitSuccess;
        }

        if (options.Error is not null)
        {
            Console.Error.WriteLine(options.Error);
            return ExitUsage;
        }

        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        // Даты в консоли и отчётах показываются в зоне машины аналитика,
        // а не в жёстко зашитой московской.
        DateDisplay.DisplayZone = TimeZoneInfo.Local;

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        await using var services = new ServiceCollection()
            .AddApplicationServices()
            .AddInfrastructureServices()
            .BuildServiceProvider();

        try
        {
            // Просмотр и сравнение уже сохранённых сессий — операции только чтения
            // локальной базы: админ-права и полный конвейер сканирования не нужны.
            if (options.ListSessions)
            {
                return PrintSessions(services);
            }

            if (options is { DiffBaseline: not null, DiffTarget: not null })
            {
                return PrintDiff(services, options.DiffBaseline, options.DiffTarget, options.JsonPath);
            }

            if (options.Verify)
            {
                return PrintIntegrity(services, options.JsonPath);
            }

            // Флот — тоже только чтение: JSON-экспорты сканирований, ни одна
            // живая система не затрагивается, поэтому админ-права не нужны.
            if (options.FleetDirectory is not null)
            {
                return PrintFleet(options.FleetDirectory, options.JsonPath);
            }

            var privilegeChecker = services.GetRequiredService<IPrivilegeChecker>();
            if (!privilegeChecker.IsAdministrator())
            {
                Console.Error.WriteLine(CliStrings.Get("AdminRequired"));
                return ExitNotAdministrator;
            }

            if (options.OfflineRoot is not null)
            {
                return RunOffline(services, options, cancellation.Token);
            }

            if (options.Monitor)
            {
                return RunMonitor(services, cancellation.Token);
            }

            return await RunAsync(services, options, cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine(CliStrings.Get("Cancelled"));
            return ExitCancelled;
        }
        catch (Exception exception)
        {
            // Последний рубеж процесса: любое необработанное исключение должно
            // превратиться в понятное сообщение и ненулевой код возврата, а не
            // в необъяснимое падение при запуске из скрипта.
            Console.Error.WriteLine(CliStrings.Format("ErrorPrefix", exception.Message));
            Console.Error.WriteLine(exception.ToString());
            return ExitFailure;
        }
    }

    private static async Task<int> RunAsync(
        ServiceProvider services,
        CliOptions options,
        CancellationToken cancellationToken)
    {
        var orchestrator = services.GetRequiredService<AuditOrchestrator>();

        IProgress<string>? progress = options.Quiet
            ? null
            : new Progress<string>(static message => Console.WriteLine(message));

        if (!options.Quiet)
        {
            Console.WriteLine(CliStrings.Get("ScanStarting"));
        }

        var result = await orchestrator.RunFullScanAsync(progress, cancellationToken);

        PrintSummary(orchestrator, result);

        if (options.JsonPath is not null)
        {
            ExportJson(result, options.JsonPath);
        }

        if (options.ReportDirectory is not null)
        {
            CreateReports(services, result, options.ReportDirectory, options.ReportFormats);
        }

        return ExitSuccess;
    }

    private static int PrintIntegrity(ServiceProvider services, string? jsonPath)
    {
        var verifier = services.GetRequiredService<IEvidenceIntegrityVerifier>();
        var storage = services.GetRequiredService<IAuditStorage>();
        var report = verifier.Verify();

        if (report.JournalMissing)
        {
            Console.WriteLine(CliStrings.Get("IntegrityJournalMissing"));
            Console.WriteLine(CliStrings.Format("IntegrityDataDirectory", storage.DataDirectory));
            return ExitSuccess;
        }

        Console.WriteLine(CliStrings.Format("IntegrityTotalRecords", report.TotalRecords));
        Console.WriteLine(CliStrings.Format("IntegrityChainBreaks", report.ChainBreaks.Count));
        var matched = report.SealChecks.Count(static c => c.Status == SealStatus.Match);
        var mismatched = report.SealChecks.Count(static c => c.Status == SealStatus.Mismatch);
        var unsealed = report.SealChecks.Count(static c => c.Status == SealStatus.NotSealed);
        Console.WriteLine(CliStrings.Format("IntegritySeals", matched, mismatched, unsealed));

        foreach (var chainBreak in report.ChainBreaks)
        {
            Console.WriteLine(CliStrings.Format("IntegrityBreakLine", chainBreak.LineNumber, chainBreak.Reason));
        }

        foreach (var check in report.SealChecks.Where(static c => c.Status == SealStatus.Mismatch))
        {
            Console.WriteLine(CliStrings.Format("IntegritySealMismatch", check.SessionId));
        }

        Console.WriteLine();
        Console.WriteLine(CliStrings.Get(report.IsIntact ? "IntegrityIntact" : "IntegrityViolated"));

        if (jsonPath is not null)
        {
            ExportJson(report, jsonPath);
        }

        return report.IsIntact ? ExitSuccess : ExitIntegrityViolation;
    }

    private static int RunOffline(ServiceProvider services, CliOptions options, CancellationToken cancellationToken)
    {
        var auditor = services.GetRequiredService<IOfflineWindowsAuditor>();
        if (!options.Quiet)
        {
            Console.WriteLine(CliStrings.Format("OfflineStarting", options.OfflineRoot));
        }

        var result = auditor.Audit(options.OfflineRoot!, cancellationToken);

        var storage = services.GetRequiredService<IAuditStorage>();
        storage.Save(result);

        Console.WriteLine();
        Console.WriteLine(CliStrings.Format("OfflineSession", result.SessionId));
        Console.WriteLine(CliStrings.Format("OfflineSystem", result.ComputerName, result.WindowsVersion));
        Console.WriteLine(CliStrings.Format("OfflineDevices", result.Devices.Count));
        Console.WriteLine(CliStrings.Format("OfflineEvidence", result.Evidence.Count));
        Console.WriteLine(CliStrings.Format("OfflineWarnings", result.SourceWarnings.Count));
        Console.WriteLine(CliStrings.Format("OfflineDatabase", storage.DatabasePath));

        if (!options.Quiet)
        {
            foreach (var warning in result.SourceWarnings)
            {
                Console.WriteLine(CliStrings.Format("WarningLine", warning));
            }
        }

        if (options.JsonPath is not null)
        {
            ExportJson(result, options.JsonPath);
        }

        if (options.ReportDirectory is not null)
        {
            CreateReports(services, result, options.ReportDirectory, options.ReportFormats);
        }

        return ExitSuccess;
    }

    private static int PrintSessions(ServiceProvider services)
    {
        var storage = services.GetRequiredService<IAuditStorage>();
        var sessions = storage.ListSessions();
        if (sessions.Count == 0)
        {
            Console.WriteLine(CliStrings.Format("SessionsEmpty", storage.DatabasePath));
            return ExitSuccess;
        }

        Console.WriteLine(
            $"{CliStrings.Get("SessionsColSession"),-34} {CliStrings.Get("SessionsColStarted"),-21} " +
            $"{CliStrings.Get("SessionsColComputer"),-16} {CliStrings.Get("SessionsColDevices"),6} " +
            $"{CliStrings.Get("SessionsColEvidence"),7} {CliStrings.Get("SessionsColCleanup"),8}");
        foreach (var session in sessions)
        {
            Console.WriteLine(
                $"{session.SessionId,-34} {session.StartedAtUtc:yyyy-MM-dd HH:mm:ss}   " +
                $"{session.ComputerName,-16} {session.DeviceCount,6} {session.EvidenceCount,7} {session.CleanupFindingCount,8}");
        }

        Console.WriteLine();
        Console.WriteLine(CliStrings.Format("SessionsTotal", sessions.Count, storage.DatabasePath));
        return ExitSuccess;
    }

    private static int PrintDiff(ServiceProvider services, string baselineId, string targetId, string? jsonPath)
    {
        var storage = services.GetRequiredService<IAuditStorage>();
        var baseline = storage.Load(baselineId);
        if (baseline is null)
        {
            Console.Error.WriteLine(CliStrings.Format("DiffSessionNotFound", baselineId));
            return ExitFailure;
        }

        var target = storage.Load(targetId);
        if (target is null)
        {
            Console.Error.WriteLine(CliStrings.Format("DiffSessionNotFound", targetId));
            return ExitFailure;
        }

        var diff = SessionDiffService.Compare(baseline, target);

        Console.WriteLine(CliStrings.Get("DiffHeader"));
        Console.WriteLine(CliStrings.Format("DiffBaselineLine", diff.Baseline.SessionId, diff.Baseline.StartedAtUtc));
        Console.WriteLine(CliStrings.Format("DiffTargetLine", diff.Target.SessionId, diff.Target.StartedAtUtc));
        Console.WriteLine();
        Console.WriteLine(CliStrings.Format("DiffAddedDevices", diff.AddedDevices.Count));
        Console.WriteLine(CliStrings.Format("DiffRemovedDevices", diff.RemovedDevices.Count));
        Console.WriteLine(CliStrings.Format("DiffAddedEvidence", diff.AddedEvidence.Count));
        Console.WriteLine(CliStrings.Format("DiffMissingEvidence", diff.MissingEvidence.Count));
        Console.WriteLine(CliStrings.Format("DiffAddedCleanup", diff.AddedCleanupFindings.Count));
        Console.WriteLine(CliStrings.Format("DiffAddedNetwork", diff.AddedNetworkConnections.Count));
        Console.WriteLine(CliStrings.Format("DiffRemovedNetwork", diff.RemovedNetworkConnections.Count));

        foreach (var device in diff.AddedDevices)
        {
            Console.WriteLine(CliStrings.Format("DiffDeviceAdded", Describe(device)));
        }

        foreach (var device in diff.RemovedDevices)
        {
            Console.WriteLine(CliStrings.Format("DiffDeviceRemoved", Describe(device)));
        }

        if (diff.MissingEvidence.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine(CliStrings.Get("DiffMissingWarning"));
        }

        if (!diff.HasChanges)
        {
            Console.WriteLine();
            Console.WriteLine(CliStrings.Get("DiffNoChanges"));
        }

        if (jsonPath is not null)
        {
            var fullPath = Path.GetFullPath(jsonPath);
            var directory = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(fullPath, JsonSerializer.Serialize(diff, JsonExportOptions), Encoding.UTF8);
            Console.WriteLine();
            Console.WriteLine(CliStrings.Format("DiffJsonExport", fullPath));
        }

        return ExitSuccess;
    }

    private static string Describe(UsbDeviceRecord device)
    {
        var name = !string.IsNullOrWhiteSpace(device.FriendlyName) ? device.FriendlyName
            : !string.IsNullOrWhiteSpace(device.Product) ? device.Product
            : device.DeviceInstanceId;
        var serial = string.IsNullOrWhiteSpace(device.Serial)
            ? ""
            : CliStrings.Format("SerialSuffix", device.Serial);
        return $"{name}{serial}";
    }

    private static void PrintSummary(AuditOrchestrator orchestrator, AuditResult result)
    {
        Console.WriteLine();
        Console.WriteLine(CliStrings.Format("SummarySession", result.SessionId));
        Console.WriteLine(CliStrings.Format("SummaryDevices", result.Devices.Count));
        Console.WriteLine(CliStrings.Format("SummaryEvidence", result.Evidence.Count));
        Console.WriteLine(CliStrings.Format("SummaryCleanup", result.CleanupFindings.Count));
        Console.WriteLine(CliStrings.Format("SummaryNetwork", result.NetworkConnections.Count));
        Console.WriteLine(CliStrings.Format("SummaryWarnings", result.SourceWarnings.Count));
        Console.WriteLine(CliStrings.Format("SummaryDatabase", orchestrator.Storage.DatabasePath));
    }

    private static void ExportJson<T>(T result, string jsonPath)
    {
        var fullPath = Path.GetFullPath(jsonPath);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var json = JsonSerializer.Serialize(result, JsonExportOptions);
        File.WriteAllText(fullPath, json, Encoding.UTF8);
        Console.WriteLine(CliStrings.Format("JsonExport", fullPath));
    }

    /// <summary>
    /// Фоновый мониторинг USB без окна: события WMI (или резервный опрос),
    /// сверка с базой известных устройств и политикой «свой/чужой». Алерты
    /// уходят в консоль, alerts.jsonl, журнал приложений Windows и вебхук из
    /// monitor-config.json. Работает до Ctrl+C — подходит для планировщика
    /// задач и автозапуска.
    /// </summary>
    private static int RunMonitor(ServiceProvider services, CancellationToken cancellationToken)
    {
        var storage = services.GetRequiredService<IAuditStorage>();
        var baseline = storage.ListKnownDeviceIdentities();
        var detector = new UnknownDeviceDetector(baseline);
        var policy = DevicePolicyProvider.LoadDefault();
        var alertOptions = MonitorAlertOptions.LoadDefault();
        var snapshotService = new LiveUsbSnapshotService();
        var alerted = new HashSet<string>(StringComparer.Ordinal);
        var evaluationLock = new object();

        Console.WriteLine(CliStrings.Get("MonitorStarted"));
        if (baseline.Count == 0)
        {
            Console.WriteLine(CliStrings.Get("MonitorBaselineEmpty"));
        }

        if (policy.IsEmpty)
        {
            Console.WriteLine(CliStrings.Get("MonitorPolicyMissing"));
        }

        void Evaluate()
        {
            lock (evaluationLock)
            {
                try
                {
                    var snapshot = snapshotService.GetCurrentDevices();
                    IReadOnlyList<LiveUsbDevice> unknown = detector.BaselineSize > 0
                        ? detector.DetectNew(snapshot)
                        : [];
                    foreach (var alert in LiveMonitorRules.Evaluate(snapshot, unknown, policy, alerted))
                    {
                        Console.WriteLine(CliStrings.Format("MonitorAlertLine",
                            DateDisplay.ToMoscow(alert.WhenUtc).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                            alert.KindText,
                            alert.Title,
                            alert.Details));
                        MonitorAlertDelivery.Deliver(alert, alertOptions, storage.DataDirectory, Console.Error.WriteLine);
                    }
                }
                catch (Exception exception)
                {
                    Console.Error.WriteLine(CliStrings.Format("ErrorPrefix", exception.Message));
                }
            }
        }

        using var monitor = new WmiUsbMonitor();
        monitor.DeviceChanged += (_, _) => Evaluate();
        monitor.RefreshRequested += (_, _) => Evaluate();
        monitor.Start();
        if (monitor.UsesPollingFallback)
        {
            Console.WriteLine(CliStrings.Get("MonitorPollingFallback"));
        }

        // Первичная сверка: если чужое устройство уже воткнуто на момент
        // старта, алерт должен прийти сразу, а не после переподключения.
        Evaluate();

        cancellationToken.WaitHandle.WaitOne();
        monitor.Stop();
        Console.WriteLine(CliStrings.Get("MonitorStopped"));
        return ExitSuccess;
    }

    /// <summary>
    /// Сводный отчёт по флоту: читает JSON-экспорты сканирований (--json) из
    /// каталога и находит носители, засветившиеся на нескольких машинах —
    /// перемещение флешки между компьютерами является сильным сигналом утечки.
    /// </summary>
    private static int PrintFleet(string directory, string? jsonPath)
    {
        var fullPath = Path.GetFullPath(directory);
        if (!Directory.Exists(fullPath))
        {
            Console.Error.WriteLine(CliStrings.Format("FleetDirectoryMissing", fullPath));
            return ExitFailure;
        }

        var results = new List<AuditResult>();
        foreach (var file in Directory.EnumerateFiles(fullPath, "*.json").OrderBy(static x => x, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                // Потоковое чтение вместо ReadAllText: на корпоративном флоте
                // экспорты бывают в несколько МБ, и загрузка каждого целиком в
                // строку давала бы пиковую память в сотни МБ (риск OOM).
                using var stream = File.OpenRead(file);
                var result = JsonSerializer.Deserialize<AuditResult>(stream);
                if (result is null)
                {
                    Console.Error.WriteLine(CliStrings.Format("FleetFileSkipped", file, "null"));
                    continue;
                }

                results.Add(result);
            }
            catch (Exception exception) when (exception is JsonException or NotSupportedException or InvalidOperationException or IOException)
            {
                // Один битый или несовместимый экспорт не должен ронять сводку
                // по остальным машинам — пропускаем с предупреждением.
                Console.Error.WriteLine(CliStrings.Format("FleetFileSkipped", file, exception.Message));
            }
        }

        if (results.Count == 0)
        {
            Console.Error.WriteLine(CliStrings.Format("FleetNoFiles", fullPath));
            return ExitFailure;
        }

        var summary = FleetAnalyzer.Analyze(results);

        Console.WriteLine(CliStrings.Format("FleetHeader", results.Count, summary.MachineCount));
        Console.WriteLine(summary.Verdict());
        Console.WriteLine();

        foreach (var device in summary.Devices)
        {
            var marker = device.IsCrossMachine ? "!" : " ";
            Console.WriteLine($"{marker} {device.DisplayName}");
            Console.WriteLine(CliStrings.Format("FleetDeviceLine",
                device.MachineCount, device.MachinesText, device.FirstSeenText, device.LastSeenText));
        }

        if (jsonPath is not null)
        {
            File.WriteAllText(
                Path.GetFullPath(jsonPath),
                JsonSerializer.Serialize(summary, JsonExportOptions),
                new UTF8Encoding(false));
            Console.WriteLine(CliStrings.Format("FleetJsonSaved", Path.GetFullPath(jsonPath)));
        }

        return ExitSuccess;
    }

    private static readonly JsonSerializerOptions JsonExportOptions = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static void CreateReports(
        ServiceProvider services,
        AuditResult result,
        string reportDirectory,
        IReadOnlyList<string> formats)
    {
        var reportService = services.GetRequiredService<IReportService>();
        var directory = Path.GetFullPath(reportDirectory);
        Directory.CreateDirectory(directory);

        foreach (var format in formats)
        {
            var path = format switch
            {
                "html" => reportService.CreateHtml(result, directory),
                "pdf" => reportService.CreatePdf(result, directory),
                "manager-pdf" => reportService.CreateManagerPdf(result, directory),
                "brief-pdf" => reportService.CreateBriefPdf(result, directory),
                "analyst-pdf" => reportService.CreateAnalystNotePdf(result, directory),
                "excel" => reportService.CreateExcel(result, directory),
                "brief-excel" => reportService.CreateBriefExcel(result, directory),
                "analyst-excel" => reportService.CreateAnalystNoteExcel(result, directory),
                _ => throw new InvalidOperationException($"Unknown report format: {format}"),
            };

            Console.WriteLine(CliStrings.Format("ReportLine", format, path));
        }
    }
}
