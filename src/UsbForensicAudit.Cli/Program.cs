using System.IO;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;

namespace UsbForensicAudit;

/// <summary>
/// Headless-запуск полного forensic-сканирования поверх того же конвейера
/// <see cref="AuditOrchestrator"/>, что и GUI. Результат сохраняется в то же
/// хранилище (SQLite + JSONL с hash-chain), дополнительно доступны экспорт в
/// JSON и генерация отчётов без открытия окна.
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
            PrintUsage();
            return ExitSuccess;
        }

        if (options.Error is not null)
        {
            Console.Error.WriteLine(options.Error);
            return ExitUsage;
        }

        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

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

            var privilegeChecker = services.GetRequiredService<IPrivilegeChecker>();
            if (!privilegeChecker.IsAdministrator())
            {
                Console.Error.WriteLine(
                    "Сканирование требует прав администратора: без них защищённые ветки реестра " +
                    "и журнал Security недоступны, а отчёт будет неполным. " +
                    "Запустите консоль от имени администратора и повторите.");
                return ExitNotAdministrator;
            }

            if (options.OfflineRoot is not null)
            {
                return RunOffline(services, options, cancellation.Token);
            }

            return await RunAsync(services, options, cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Сканирование прервано пользователем.");
            return ExitCancelled;
        }
        catch (Exception exception)
        {
            // Последний рубеж процесса: любое необработанное исключение должно
            // превратиться в понятное сообщение и ненулевой код возврата, а не
            // в необъяснимое падение при запуске из скрипта.
            Console.Error.WriteLine($"Ошибка сканирования: {exception.Message}");
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
            Console.WriteLine("Запуск полного сканирования...");
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
            Console.WriteLine("Журнал доказательств отсутствует: сканирований ещё не было.");
            Console.WriteLine($"Каталог данных: {storage.DataDirectory}");
            return ExitSuccess;
        }

        Console.WriteLine($"Записей в журнале:    {report.TotalRecords}");
        Console.WriteLine($"Разрывов hash-chain:  {report.ChainBreaks.Count}");
        var matched = report.SealChecks.Count(static c => c.Status == SealStatus.Match);
        var mismatched = report.SealChecks.Count(static c => c.Status == SealStatus.Mismatch);
        var unsealed = report.SealChecks.Count(static c => c.Status == SealStatus.NotSealed);
        Console.WriteLine($"Печати сессий:        {matched} совпало, {mismatched} расхождений, {unsealed} без печати");

        foreach (var chainBreak in report.ChainBreaks)
        {
            Console.WriteLine($"  ! строка {chainBreak.LineNumber}: {chainBreak.Reason}");
        }

        foreach (var check in report.SealChecks.Where(static c => c.Status == SealStatus.Mismatch))
        {
            Console.WriteLine($"  ! сессия {check.SessionId}: печать в базе не совпадает с журналом.");
        }

        Console.WriteLine();
        Console.WriteLine(report.IsIntact
            ? "Целостность подтверждена: доказательная база не изменялась."
            : "ЦЕЛОСТНОСТЬ НАРУШЕНА: записи изменялись после сохранения.");

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
            Console.WriteLine($"Офлайн-анализ: {options.OfflineRoot}...");
        }

        var result = auditor.Audit(options.OfflineRoot!, cancellationToken);

        var storage = services.GetRequiredService<IAuditStorage>();
        storage.Save(result);

        Console.WriteLine();
        Console.WriteLine($"Сессия:               {result.SessionId}");
        Console.WriteLine($"Исследуемая система:  {result.ComputerName} ({result.WindowsVersion})");
        Console.WriteLine($"Устройств найдено:    {result.Devices.Count}");
        Console.WriteLine($"Доказательств:        {result.Evidence.Count}");
        Console.WriteLine($"Предупреждений:       {result.SourceWarnings.Count}");
        Console.WriteLine($"База данных:          {storage.DatabasePath}");

        if (!options.Quiet)
        {
            foreach (var warning in result.SourceWarnings)
            {
                Console.WriteLine($"  ! {warning}");
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
            Console.WriteLine($"Сохранённых сессий нет. База: {storage.DatabasePath}");
            return ExitSuccess;
        }

        Console.WriteLine($"{"Сессия",-34} {"Начало (UTC)",-21} {"Компьютер",-16} {"Устр.",6} {"Доказ.",7} {"Очистки",8}");
        foreach (var session in sessions)
        {
            Console.WriteLine(
                $"{session.SessionId,-34} {session.StartedAtUtc:yyyy-MM-dd HH:mm:ss}   " +
                $"{session.ComputerName,-16} {session.DeviceCount,6} {session.EvidenceCount,7} {session.CleanupFindingCount,8}");
        }

        Console.WriteLine();
        Console.WriteLine($"Всего сессий: {sessions.Count}. База: {storage.DatabasePath}");
        return ExitSuccess;
    }

    private static int PrintDiff(ServiceProvider services, string baselineId, string targetId, string? jsonPath)
    {
        var storage = services.GetRequiredService<IAuditStorage>();
        var baseline = storage.Load(baselineId);
        if (baseline is null)
        {
            Console.Error.WriteLine($"Сессия не найдена: {baselineId}. Список сессий: --list-sessions.");
            return ExitFailure;
        }

        var target = storage.Load(targetId);
        if (target is null)
        {
            Console.Error.WriteLine($"Сессия не найдена: {targetId}. Список сессий: --list-sessions.");
            return ExitFailure;
        }

        var diff = SessionDiffService.Compare(baseline, target);

        Console.WriteLine("Сравнение сессий (базовая -> целевая):");
        Console.WriteLine($"  Базовая: {diff.Baseline.SessionId} от {diff.Baseline.StartedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"  Целевая: {diff.Target.SessionId} от {diff.Target.StartedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine();
        Console.WriteLine($"Новые устройства:            {diff.AddedDevices.Count}");
        Console.WriteLine($"Исчезнувшие устройства:      {diff.RemovedDevices.Count}");
        Console.WriteLine($"Новые доказательства:        {diff.AddedEvidence.Count}");
        Console.WriteLine($"Исчезнувшие доказательства:  {diff.MissingEvidence.Count}");
        Console.WriteLine($"Новые признаки очистки:      {diff.AddedCleanupFindings.Count}");
        Console.WriteLine($"Новые сетевые связи:         {diff.AddedNetworkConnections.Count}");
        Console.WriteLine($"Исчезнувшие сетевые связи:   {diff.RemovedNetworkConnections.Count}");

        foreach (var device in diff.AddedDevices)
        {
            Console.WriteLine($"  + устройство: {Describe(device)}");
        }

        foreach (var device in diff.RemovedDevices)
        {
            Console.WriteLine($"  - устройство: {Describe(device)}");
        }

        if (diff.MissingEvidence.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine(
                "Внимание: часть доказательств из базовой сессии не найдена в целевой. " +
                "Артефакты не исчезают сами: проверьте ротацию журналов и признаки очистки следов.");
        }

        if (!diff.HasChanges)
        {
            Console.WriteLine();
            Console.WriteLine("Изменений между сессиями не обнаружено.");
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
            Console.WriteLine($"JSON-экспорт diff:     {fullPath}");
        }

        return ExitSuccess;
    }

    private static string Describe(UsbDeviceRecord device)
    {
        var name = !string.IsNullOrWhiteSpace(device.FriendlyName) ? device.FriendlyName
            : !string.IsNullOrWhiteSpace(device.Product) ? device.Product
            : device.DeviceInstanceId;
        var serial = string.IsNullOrWhiteSpace(device.Serial) ? "" : $" (S/N: {device.Serial})";
        return $"{name}{serial}";
    }

    private static void PrintSummary(AuditOrchestrator orchestrator, AuditResult result)
    {
        Console.WriteLine();
        Console.WriteLine($"Сессия:                {result.SessionId}");
        Console.WriteLine($"Устройств:             {result.Devices.Count}");
        Console.WriteLine($"Доказательств:         {result.Evidence.Count}");
        Console.WriteLine($"Признаков очистки:     {result.CleanupFindings.Count}");
        Console.WriteLine($"Сетевых связей:        {result.NetworkConnections.Count}");
        Console.WriteLine($"Предупреждений:        {result.SourceWarnings.Count}");
        Console.WriteLine($"База результатов:      {orchestrator.Storage.DatabasePath}");
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
        Console.WriteLine($"JSON-экспорт:          {fullPath}");
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
                "brief-pdf" => reportService.CreateBriefPdf(result, directory),
                "analyst-pdf" => reportService.CreateAnalystNotePdf(result, directory),
                "excel" => reportService.CreateExcel(result, directory),
                "brief-excel" => reportService.CreateBriefExcel(result, directory),
                "analyst-excel" => reportService.CreateAnalystNoteExcel(result, directory),
                _ => throw new InvalidOperationException($"Unknown report format: {format}"),
            };

            Console.WriteLine($"Отчёт ({format,-13}): {path}");
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            UsbForensicAudit.Cli — headless-сканирование USB-артефактов.

            Использование:
              UsbForensicAudit.Cli.exe [параметры]

            Параметры:
              --json <файл>       сохранить полный результат сканирования в JSON
                                  (с --diff сохраняет отчёт сравнения)
              --reports <каталог> сгенерировать отчёты в указанный каталог
              --formats <список>  форматы отчётов через запятую (по умолчанию: html,pdf)
                                  допустимые: html, pdf, brief-pdf, analyst-pdf,
                                  excel, brief-excel, analyst-excel
              --list-sessions     показать сохранённые сессии и выйти (без сканирования)
              --diff <баз> <цел>  сравнить две сохранённые сессии: что появилось
                                  и что исчезло между сканированиями
              --offline <корень>  офлайн-анализ чужой системы: смонтированный
                                  образ диска (например, F:\) или скопированный
                                  каталог Windows; анализируются только кусты
                                  рее��тра, исследуемые файлы не изменяются
              --verify            проверить целостность доказательной базы:
                                  пересчитать hash-chain журнала и сверить
                                  печати сессий с базой (с --json сохраняет
                                  отчёт верификации)
              --quiet, -q         не печатать пошаговый прогресс
              --help, -h          показать эту справку

            Коды возврата:
              0  сканирование завершено успешно
              1  ошибка выполнения
              2  нет прав администратора
              3  прервано пользователем (Ctrl+C)
              4  верификация нашла нарушения целостности
              64 неверные аргументы

            Результат всегда сохраняется в базу data\audit.sqlite рядом с exe —
            той же, что использует GUI-приложение.
            """);
    }
}
