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

        var privilegeChecker = services.GetRequiredService<IPrivilegeChecker>();
        if (!privilegeChecker.IsAdministrator())
        {
            Console.Error.WriteLine(
                "Сканирование требует прав администратора: без них защищённые ветки реестра " +
                "и журнал Security недоступны, а отчёт будет неполным. " +
                "Запустите консоль от имени администратора и повторите.");
            return ExitNotAdministrator;
        }

        try
        {
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

    private static void ExportJson(AuditResult result, string jsonPath)
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
              --reports <каталог> сгенерировать отчёты в указанный каталог
              --formats <список>  форматы отчётов через запятую (по умолчанию: html,pdf)
                                  допустимые: html, pdf, brief-pdf, analyst-pdf,
                                  excel, brief-excel, analyst-excel
              --quiet, -q         не печатать пошаговый прогресс
              --help, -h          показать эту справку

            Коды возврата:
              0  сканирование завершено успешно
              1  ошибка выполнения
              2  нет прав администратора
              3  прервано пользователем (Ctrl+C)
              64 неверные аргументы

            Результат всегда сохраняется в базу data\audit.sqlite рядом с exe —
            той же, что использует GUI-приложение.
            """);
    }
}
