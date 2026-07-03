using System.Diagnostics;
using System.IO;

namespace UsbForensicAudit;

public sealed class ProcmonTraceRequest
{
    public required ExternalUtilityRow Row { get; init; }
    public required string UtilityProcessName { get; init; }
    public int? UtilityProcessId { get; init; }
    public string? UtilityId { get; init; }
    public TimeSpan CaptureDuration { get; init; } = TimeSpan.FromSeconds(20);
}

public sealed class ProcmonTraceResult
{
    public required IReadOnlyList<ExternalUtilitySourceHit> Hits { get; init; }
    public required string SessionDirectory { get; init; }
    public required string SummaryForReport { get; init; }
    public string? CsvPath { get; init; }
    public string? PmlPath { get; init; }
    public int ParsedEventCount { get; init; }
}

public static class ProcmonTraceService
{
    public static async Task<ProcmonTraceResult> TraceAsync(
        ProcmonTraceRequest request,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (!AdminHelper.IsAdministrator())
        {
            throw new InvalidOperationException("Procmon требует запуска UsbForensicAudit от администратора.");
        }

        var utilityProcess = ResolveUtilityProcess(request);
        if (utilityProcess is null)
        {
            throw new InvalidOperationException(
                $"Процесс «{request.UtilityProcessName}» не найден. Запустите утилиту, выполните поиск/обновление списка и повторите трассировку.");
        }

        var procmonPath = await ProcmonBootstrap.EnsureProcmonAsync(progress, cancellationToken);
        var sessionDirectory = CreateSessionDirectory();
        var pmlPath = Path.Combine(sessionDirectory, "capture.pml");
        var csvPath = Path.Combine(sessionDirectory, "capture.csv");

        progress?.Report($"Запись Procmon для {utilityProcess.ProcessName} (PID {utilityProcess.Id})…");
        progress?.Report("USBDetector/USBDeview: повторное сканирование запустится автоматически.");

        await RunProcmonCaptureAsync(
            procmonPath,
            pmlPath,
            utilityProcess,
            request.UtilityId,
            request.CaptureDuration,
            progress,
            cancellationToken);

        progress?.Report("Экспорт Procmon в CSV…");
        ExportProcmonLog(procmonPath, pmlPath, csvPath);

        var identifier = ExternalUtilityIdentifierParser.Parse(request.Row);
        var events = ProcmonCsvParser.ParseFile(csvPath);
        var hits = ProcmonCsvParser.ToSourceHits(events, request.Row, identifier, utilityProcess.ProcessName);

        if (hits.Count == 0)
        {
            var utilityEvents = events.Count(e =>
            {
                var eventBaseName = Path.GetFileNameWithoutExtension(e.ProcessName);
                return e.Operation.StartsWith("Reg", StringComparison.OrdinalIgnoreCase)
                       && (e.ProcessName.Equals(utilityProcess.ProcessName, StringComparison.OrdinalIgnoreCase)
                           || eventBaseName.Equals(Path.GetFileNameWithoutExtension(utilityProcess.ProcessName), StringComparison.OrdinalIgnoreCase));
            });

            SaveSessionReadme(sessionDirectory, request, utilityProcess, "Procmon: совпадений с выбранной строкой не найдено.", hits);

            throw new InvalidOperationException(
                utilityEvents == 0
                    ? "Procmon записал трассировку, но USBDetector/USBDeview не читали реестр во время записи. " +
                      "Оставьте окно утилиты открытым и развёрнутым (не свёрнуто), затем повторите «Жёсткую трассировку». " +
                      "Программа сама нажимает кнопки сканирования — вручную ничего искать не нужно. " +
                      $"Файлы: {sessionDirectory}"
                    : "Procmon записал чтения реестра утилитой, но совпадений с выбранной строкой не найдено. " +
                      $"Файлы сохранены: {sessionDirectory}");
        }

        var summary = ProcmonReportBuilder.BuildSummary(request.Row, identifier, hits);
        SaveSessionReadme(sessionDirectory, request, utilityProcess, summary, hits);

        return new ProcmonTraceResult
        {
            Hits = hits,
            SessionDirectory = sessionDirectory,
            SummaryForReport = summary,
            CsvPath = csvPath,
            PmlPath = pmlPath,
            ParsedEventCount = events.Count
        };
    }

    private static Process? ResolveUtilityProcess(ProcmonTraceRequest request)
    {
        if (request.UtilityProcessId is int pid)
        {
            try
            {
                var byId = Process.GetProcessById(pid);
                if (!byId.HasExited)
                {
                    return byId;
                }
            }
            catch
            {
                // Fall back to name lookup.
            }
        }

        var processName = Path.GetFileNameWithoutExtension(request.UtilityProcessName);
        return Process.GetProcessesByName(processName).FirstOrDefault(x => !x.HasExited);
    }

    private static string CreateSessionDirectory()
    {
        var root = AppPaths.ProcmonDirectory;
        Directory.CreateDirectory(root);
        var sessionDirectory = Path.Combine(root, DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss"));
        Directory.CreateDirectory(sessionDirectory);
        return sessionDirectory;
    }

    private static async Task RunProcmonCaptureAsync(
        string procmonPath,
        string pmlPath,
        Process utilityProcess,
        string? utilityId,
        TimeSpan duration,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        if (File.Exists(pmlPath))
        {
            File.Delete(pmlPath);
        }

        using var procmon = Process.Start(new ProcessStartInfo
        {
            FileName = procmonPath,
            Arguments = $"/AcceptEula /Quiet /Minimized /BackingFile \"{pmlPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true
        }) ?? throw new InvalidOperationException("Не удалось запустить Procmon.");

        try
        {
            var rescanAttempts = new List<string>();
            progress?.Report("Procmon: автоматический запуск сканирования в USBDetector…");

            for (var attempt = 0; attempt < 4; attempt++)
            {
                utilityProcess.Refresh();
                if (utilityProcess.HasExited)
                {
                    break;
                }

                var rescan = ExternalUtilityWindowAutomation.TryTriggerRescan(utilityProcess, utilityId ?? "");
                rescanAttempts.Add(rescan.Details);
                progress?.Report(rescan.Triggered
                    ? $"Procmon: сканирование в утилите запущено ({rescan.Details})."
                    : $"Procmon: попытка {attempt + 1}/4 — {rescan.Details}");

                if (rescan.Triggered)
                {
                    break;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(700), cancellationToken);
            }

            var seconds = (int)Math.Ceiling(duration.TotalSeconds);
            for (var second = seconds; second > 0; second--)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (second == seconds - 8 || second == seconds - 16)
                {
                    utilityProcess.Refresh();
                    if (!utilityProcess.HasExited)
                    {
                        ExternalUtilityWindowAutomation.TryTriggerRescan(utilityProcess, utilityId ?? "");
                    }
                }

                progress?.Report($"Запись Procmon… {second} сек.");
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            }
        }
        finally
        {
            TryRunProcmon(procmonPath, $"/Terminate /AcceptEula /Quiet");
            try
            {
                if (!procmon.HasExited)
                {
                    procmon.WaitForExit(5000);
                }
            }
            catch
            {
                // Ignore shutdown races.
            }
        }

        if (!File.Exists(pmlPath))
        {
            throw new InvalidOperationException("Procmon не создал файл трассировки (.pml).");
        }
    }

    private static void ExportProcmonLog(string procmonPath, string pmlPath, string csvPath)
    {
        if (File.Exists(csvPath))
        {
            File.Delete(csvPath);
        }

        var exported = TryRunProcmon(
            procmonPath,
            $"/OpenLog \"{pmlPath}\" /SaveAs \"{csvPath}\" /AcceptEula /Quiet",
            csvPath);
        if (!exported)
        {
            throw new InvalidOperationException("Procmon не смог экспортировать CSV. Проверьте, что Procmon64.exe доступен.");
        }
    }

    private static bool TryRunProcmon(string procmonPath, string arguments, string? expectedOutputPath = null)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = procmonPath,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true
            });

            process?.WaitForExit(120_000);

            if (!string.IsNullOrWhiteSpace(expectedOutputPath) && File.Exists(expectedOutputPath))
            {
                return true;
            }

            return process?.ExitCode == 0;
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Procmon command failed: " + arguments);
            return false;
        }
    }

    private static void SaveSessionReadme(
        string sessionDirectory,
        ProcmonTraceRequest request,
        Process utilityProcess,
        string summary,
        IReadOnlyList<ExternalUtilitySourceHit> hits)
    {
        var lines = new List<string>
        {
            "UsbForensicAudit — Procmon session",
            $"CapturedAtUtc={DateTimeOffset.UtcNow:O}",
            $"Utility={utilityProcess.ProcessName} PID={utilityProcess.Id}",
            $"Row={request.Row.SectionTitle} / {request.Row.PrimaryText}",
            "",
            summary,
            "",
            "Hits:"
        };
        lines.AddRange(hits.Select(x => x.DisplayLine));
        File.WriteAllLines(Path.Combine(sessionDirectory, "README.txt"), lines);
    }
}
