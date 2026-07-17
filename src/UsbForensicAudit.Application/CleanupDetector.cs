using System.IO;
using System.Diagnostics.CodeAnalysis;

namespace UsbForensicAudit;

public sealed class CleanupDetector
{
    [SuppressMessage(
        "Performance",
        "CA1822:Mark members as static",
        Justification = "The detector is an injected application service and intentionally exposes an instance API.")]
    public IReadOnlyList<CleanupFinding> Analyze(AuditResult result)
    {
        var findings = new List<CleanupFinding>();
        AnalyzeSetupApi(findings, result);
        AnalyzeEventLogEvidence(result, findings);
        AnalyzeCleanerEvidence(result, findings);
        AnalyzeExecutionGaps(result, findings);
        UsbOblivionAttributionAnalyzer.Analyze(result, findings);
        AnalyzeContradictions(result, findings);
        return findings;
    }

    private static void AnalyzeSetupApi(List<CleanupFinding> findings, AuditResult result)
    {
        var installAtUtc = result.OsInstalledAtUtc;
        var scanAtUtc = result.StartedAtUtc;
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "inf", "setupapi.dev.log");
        if (!File.Exists(path))
        {
            findings.Add(ApplyAttribution(
                CreateFinding(installAtUtc, scanAtUtc, "High", "SetupAPI",
                    "setupapi.dev.log отсутствует",
                    $"Файл {path} не найден. Это может быть следствием очистки или нестандартного состояния системы.",
                    scanAtUtc),
                result,
                scanAtUtc,
                InitiatorInfo.Unknown,
                null,
                fromInitialSetup: false));
            return;
        }

        var info = new FileInfo(path);
        var fileCreatedUtc = new DateTimeOffset(info.CreationTimeUtc, TimeSpan.Zero);
        var fromInitialSetup = IsFromInitialWindowsSetup(info.CreationTimeUtc, installAtUtc);
        var correlatedTool = CleanupAttribution.FindCorrelatedTool(fileCreatedUtc, result.Evidence);

        if (fromInitialSetup)
        {
            var initiator = CleanupAttribution.InitiatorForSetupApi(true, installAtUtc);
            var osFinding = CreateOsInstallFinding(fileCreatedUtc, "SetupAPI",
                "setupapi.dev.log создан при установке Windows",
                $"Создан: {DateDisplay.FormatMoscow(fileCreatedUtc)}, изменен: {DateDisplay.FormatMoscow(info.LastWriteTimeUtc)}.");
            osFinding.InitiatorKind = initiator.Kind;
            osFinding.InitiatorAccount = initiator.Account;
            osFinding.PossibleTool = CleanupAttribution.ToolForSetupApi(true, correlatedTool);
            osFinding.Details += $" {CleanupAttribution.BuildAttributionDetails(initiator, osFinding.PossibleTool, osFinding.Confidence)}";
            findings.Add(osFinding);
        }

        if (info.Length < 32 * 1024 && !fromInitialSetup)
        {
            var initiator = CleanupAttribution.InitiatorForSetupApi(false, installAtUtc);
            findings.Add(ApplyAttribution(
                CreateFinding(installAtUtc, fileCreatedUtc, "Medium", "SetupAPI",
                    "setupapi.dev.log подозрительно мал",
                    $"Размер файла: {info.Length:N0} байт. Для активно используемой Windows это может указывать на пересоздание или очистку.",
                    fileCreatedUtc),
                result,
                fileCreatedUtc,
                initiator,
                correlatedTool,
                false));
        }

        if (installAtUtc is not null
            && info.CreationTimeUtc > installAtUtc.Value.Add(OsInstallInfo.PostInstallGracePeriod))
        {
            findings.Add(ApplyAttribution(
                CreateFinding(installAtUtc, fileCreatedUtc, "Medium", "SetupAPI",
                    "setupapi.dev.log пересоздан после установки Windows",
                    $"Установка Windows: {OsInstallInfo.FormatInstallDate(installAtUtc)}. Файл создан: {DateDisplay.FormatMoscow(fileCreatedUtc)}. Прошло более {OsInstallInfo.PostInstallGraceHours} ч. с установки — пересоздание может быть признаком очистки.",
                    fileCreatedUtc),
                result,
                fileCreatedUtc,
                InitiatorInfo.Unknown,
                correlatedTool,
                false));
        }
        else if (installAtUtc is null
                 && info.CreationTimeUtc > DateTime.UtcNow.AddDays(-7)
                 && Directory.GetCreationTimeUtc(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) < DateTime.UtcNow.AddDays(-30))
        {
            findings.Add(ApplyAttribution(
                CreateFinding(installAtUtc, fileCreatedUtc, "Medium", "SetupAPI",
                    "setupapi.dev.log создан недавно",
                    $"Создан: {info.CreationTime:u}, изменен: {info.LastWriteTime:u}. На старой системе это может быть признаком пересоздания файла.",
                    fileCreatedUtc),
                result,
                fileCreatedUtc,
                InitiatorInfo.Unknown,
                correlatedTool,
                false));
        }
    }

    private static void AnalyzeEventLogEvidence(AuditResult result, List<CleanupFinding> findings)
    {
        var installAtUtc = result.OsInstalledAtUtc;

        foreach (var evidence in result.Evidence.Where(x => x.EventId is "104" or "1102"))
        {
            var initiator = CleanupAttribution.ParseEventLogInitiator(evidence.RawText);
            var correlatedTool = CleanupAttribution.FindCorrelatedTool(evidence.TimestampUtc, result.Evidence);
            var baseDetails = $"{evidence.Source}: {evidence.Summary}";
            var finding = CreateFinding(
                installAtUtc,
                evidence.TimestampUtc,
                evidence.EventId == "1102" ? "High" : "Medium",
                "Event Logs",
                $"Найдено событие очистки журнала Event ID {evidence.EventId}",
                baseDetails,
                evidence.TimestampUtc);
            if (finding.Assessment == "OsInstall")
            {
                if (initiator.Kind == "Unknown")
                {
                    initiator = new InitiatorInfo("System", "SYSTEM (Windows Setup)", "S-1-5-18");
                }

                finding.InitiatorKind = initiator.Kind;
                finding.InitiatorAccount = initiator.Account;
                finding.PossibleTool = CleanupAttribution.ToolForSetupApi(true, correlatedTool);
                finding.Details += $" {CleanupAttribution.BuildAttributionDetails(initiator, finding.PossibleTool, finding.Confidence)}";
                findings.Add(finding);
                continue;
            }

            findings.Add(ApplyAttribution(
                finding,
                result,
                evidence.TimestampUtc,
                initiator,
                correlatedTool,
                false));
        }
    }

    private static void AnalyzeContradictions(AuditResult result, List<CleanupFinding> findings)
    {
        var usbStorDevices = result.Devices.Count(x =>
            x.Source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
            && !x.VisualCategory.Equals("HistoricalResidual", StringComparison.OrdinalIgnoreCase));
        var setupApiUsb = result.Evidence.Count(x => x.Source.Contains("setupapi", StringComparison.OrdinalIgnoreCase));
        var hasNormalMigrationContext = result.Evidence.Any(x =>
            x.Source.Contains("Windows.old", StringComparison.OrdinalIgnoreCase)
            || x.Source.Contains("offline hive", StringComparison.OrdinalIgnoreCase)
            || x.Source.Equals("ControlSet differential", StringComparison.OrdinalIgnoreCase));

        if (usbStorDevices > 0 && setupApiUsb == 0)
        {
            findings.Add(new CleanupFinding
            {
                Severity = hasNormalMigrationContext ? "Info" : "Medium",
                Assessment = hasNormalMigrationContext ? "Informational" : "Suspicious",
                InitiatorKind = "Unknown",
                InitiatorAccount = "не определено",
                PossibleTool = "не определено",
                Confidence = "Indirect",
                ActionKind = hasNormalMigrationContext ? "NormalMigrationContext" : "Correlation",
                Area = "Correlation",
                Finding = "USBSTOR есть в реестре, но нет USB-записей SetupAPI",
                Details = $"Найдено USBSTOR-устройств: {usbStorDevices}. В setupapi.dev.log релевантных USB-записей не найдено. " +
                          (hasNormalMigrationContext
                              ? "Обнаружен контекст миграции/ротации Windows; различие не трактуется как очистка без независимого подтверждения."
                              : CleanupAttribution.BuildAttributionDetails(InitiatorInfo.Unknown, null, "Indirect"))
            });
        }

        var mountedHints = result.Devices.Any(x => x.Source.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase));
        var usbDevices = result.Devices.Count(x =>
            x.Source.Contains("USB", StringComparison.OrdinalIgnoreCase)
            && !x.VisualCategory.Equals("HistoricalResidual", StringComparison.OrdinalIgnoreCase));
        if (mountedHints && usbDevices == 0)
        {
            findings.Add(new CleanupFinding
            {
                Severity = hasNormalMigrationContext ? "Info" : "Low",
                Assessment = hasNormalMigrationContext ? "Informational" : "Suspicious",
                InitiatorKind = "Unknown",
                InitiatorAccount = "не определено",
                PossibleTool = "не определено",
                Confidence = "Indirect",
                ActionKind = hasNormalMigrationContext ? "NormalMigrationContext" : "Correlation",
                Area = "Correlation",
                Finding = "Есть MountedDevices, но нет USB-устройств",
                Details = hasNormalMigrationContext
                    ? "Есть признаки миграции/ротации Windows; состояние сохранено как нейтральное различие и не считается подтверждением очистки."
                    : $"Это может быть нормальным состоянием или следствием удаления Enum\\USB/USBSTOR. {CleanupAttribution.BuildAttributionDetails(InitiatorInfo.Unknown, null, "Indirect")}"
            });
        }
    }

    private static void AnalyzeExecutionGaps(AuditResult result, List<CleanupFinding> findings)
    {
        var corroborationSources = new[] { "BAM_EXECUTION", "DAM_EXECUTION" };
        var toolsWithCorroboration = result.Evidence
            .Where(x => corroborationSources.Contains(x.EventId, StringComparer.OrdinalIgnoreCase)
                        || x.Source.Contains("UserAssist", StringComparison.OrdinalIgnoreCase)
                        || x.Source.Contains("MuiCache", StringComparison.OrdinalIgnoreCase))
            .Select(x => new { Evidence = x, Assessment = CleanerEvidenceClassifier.Analyze(x) })
            .Where(x => x.Assessment?.SupportsExecution == true
                        && CleanerToolCatalog.IsTraceRemovalTool(x.Assessment.Tool))
            .GroupBy(x => x.Assessment!.Tool, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        foreach (var group in toolsWithCorroboration)
        {
            var tool = group.Key;
            var latest = group.OrderByDescending(x => x.Evidence.TimestampUtc).First();
            var hasPrefetch = result.Evidence.Any(x =>
                x.EventId is "CLEANER_EXECUTION" or "CLEANER_PREFETCH_TAMPER"
                && string.Equals(CleanerEvidenceClassifier.Analyze(x)?.Tool, tool, StringComparison.OrdinalIgnoreCase));
            if (hasPrefetch)
            {
                continue;
            }

            var alreadyCovered = findings.Any(x =>
                x.PossibleTool.Equals(tool, StringComparison.OrdinalIgnoreCase)
                && x.ActionKind is "ToolLaunch" or "ProbableCleanup" or "ToolPresence");
            if (alreadyCovered)
            {
                continue;
            }

            findings.Add(new CleanupFinding
            {
                TimestampUtc = latest.Evidence.TimestampUtc,
                Severity = "Medium",
                Assessment = "Suspicious",
                ActionKind = "ExecutionGap",
                InitiatorKind = string.IsNullOrWhiteSpace(latest.Evidence.ResolvedUserName) ? "Unknown" : "User",
                InitiatorAccount = string.IsNullOrWhiteSpace(latest.Evidence.ResolvedUserName)
                    ? "не определено"
                    : latest.Evidence.ResolvedUserName,
                PossibleTool = tool,
                Confidence = "Indirect",
                Area = "Cleaner Artifacts",
                Finding = $"{tool}: запуск подтверждён BAM/UserAssist/MuiCache, но Prefetch отсутствует",
                Details =
                    "BAM/DAM, UserAssist или MuiCache указывают на запуск утилиты очистки, однако соответствующий Prefetch не найден. " +
                    "Это может быть следствием отключённого Prefetch, очистки каталога Prefetch или анти-forensic действий. " +
                    $"{latest.Evidence.Source}: {latest.Evidence.Summary}."
            });
        }
    }

    private static void AnalyzeCleanerEvidence(AuditResult result, List<CleanupFinding> findings)
    {
        var candidates = result.Evidence
            .Select(evidence => new
            {
                Evidence = evidence,
                Assessment = CleanerEvidenceClassifier.Analyze(evidence)
            })
            .Where(x => x.Assessment is not null)
            .Select(x => (x.Evidence, Assessment: x.Assessment!))
            .OrderByDescending(x => x.Evidence.TimestampUtc)
            .ToArray();
        var toolsWithExecution = candidates
            .Where(x => x.Assessment.SupportsExecution)
            .Select(x => x.Assessment.Tool)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var presenceRecorded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var launchCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var (evidence, assessment) in candidates)
        {
            var tool = assessment.Tool;
            if (!assessment.SupportsExecution)
            {
                if (toolsWithExecution.Contains(tool) || !presenceRecorded.Add(tool))
                {
                    continue;
                }

                findings.Add(CreateCleanerPresenceFinding(evidence, assessment));
                continue;
            }

            launchCounts.TryGetValue(tool, out var launchCount);
            if (launchCount >= 100)
            {
                continue;
            }

            launchCounts[tool] = launchCount + 1;
            var isUsbTool = CleanerToolCatalog.IsUsbForensicUtility(tool);
            var removesTraces = CleanerToolCatalog.IsTraceRemovalTool(tool);
            var explicitRemovalIntent = CleanerEvidenceClassifier.HasExplicitRemovalIntent(evidence, assessment);
            var readOnlyPrefetchTamper = evidence.EventId == "CLEANER_PREFETCH_TAMPER";
            var correlatedLogClear = result.Evidence.Any(x =>
                x.EventId is "104" or "1102"
                && Math.Abs((x.TimestampUtc - evidence.TimestampUtc).TotalHours) <= 2);
            var correlatedRegistryIssue = result.CleanupFindings.Concat(findings).Any(x =>
                x.Area is "SetupAPI" or "Correlation"
                && x.Assessment == "Suspicious"
                && Math.Abs((x.TimestampUtc - evidence.TimestampUtc).TotalHours) <= 24);

            var hasDirectExecutionEvidence = result.Evidence.Any(x =>
                x.EventId is "CLEANER_EXECUTION" or "CLEANER_PREFETCH_TAMPER" or "PROCESS_HINT" or "LIVE_PROCESS"
                && string.Equals(CleanerEvidenceClassifier.Analyze(x)?.Tool, tool, StringComparison.OrdinalIgnoreCase));
            var missingPrefetchNote = !hasDirectExecutionEvidence && !assessment.IsDirectExecution
                ? " BAM/UserAssist/MuiCache подтверждают запуск, но Prefetch не найден — возможна очистка каталога Prefetch или отключённый Prefetch."
                : "";
            var probableCleanup = explicitRemovalIntent
                                  || readOnlyPrefetchTamper
                                  || (removesTraces && correlatedLogClear)
                                  || (CleanerToolCatalog.IsOblivionTool(tool) && correlatedRegistryIssue);
            var existing = findings.FirstOrDefault(x =>
                x.PossibleTool.Equals(tool, StringComparison.OrdinalIgnoreCase)
                && x.ActionKind is "ToolLaunch" or "ProbableCleanup"
                && Math.Abs((x.TimestampUtc - evidence.TimestampUtc).TotalMinutes) <= 5);
            if (existing is not null)
            {
                MergeCleanerEvidence(existing, evidence, assessment, probableCleanup);
                continue;
            }

            var initiator = InitiatorFromEvidence(evidence);
            var confidence = probableCleanup
                ? "Probable"
                : assessment.IsDirectExecution ? "Confirmed" : "Probable";
            findings.Add(new CleanupFinding
            {
                TimestampUtc = evidence.TimestampUtc,
                Severity = probableCleanup ? "High" : removesTraces ? "Medium" : isUsbTool ? "Low" : "Medium",
                Assessment = removesTraces || probableCleanup ? "Suspicious" : "Informational",
                ActionKind = probableCleanup ? "ProbableCleanup" : "ToolLaunch",
                InitiatorKind = initiator.Kind,
                InitiatorAccount = initiator.Account,
                PossibleTool = tool,
                Confidence = confidence,
                Area = "Cleaner Artifacts",
                Finding = probableCleanup
                    ? $"Запуск {tool} с дополнительными признаками возможной очистки"
                    : removesTraces
                        ? $"Зафиксирован запуск утилиты очистки {tool}"
                    : isUsbTool
                        ? $"Запуск USB-утилиты {tool}"
                        : $"Зафиксирован запуск {tool}",
                Details =
                    $"{CleanerEvidenceClassifier.DescribeSource(evidence, assessment)} " +
                    $"{evidence.Source}: {evidence.Summary}; {evidence.DeviceHint}. " +
                    (probableCleanup
                        ? explicitRemovalIntent
                            ? "В командной строке найдены параметры или команда, явно направленные на удаление следов. Создание процесса не доказывает успешное завершение операции."
                            : readOnlyPrefetchTamper
                                ? "Prefetch помечен read-only — типичный признак попытки зафиксировать или скрыть след запуска."
                            : "По времени рядом найдены независимые признаки очистки журналов или USB-артефактов."
                        : removesTraces
                            ? "Запуск подтверждён, но без независимого изменения системных артефактов нельзя утверждать, что очистка завершилась."
                            : "Утилита может использоваться для просмотра или управления устройствами; её запуск не равен очистке.") +
                    " " +
                    CleanupAttribution.BuildAttributionDetails(initiator, tool, confidence) +
                    missingPrefetchNote
            });
        }
    }

    private static CleanupFinding CreateCleanerPresenceFinding(
        EvidenceRecord evidence,
        CleanerEvidenceAssessment assessment)
    {
        return new CleanupFinding
        {
            TimestampUtc = evidence.TimestampUtc,
            Severity = "Info",
            Assessment = "Informational",
            ActionKind = "ToolPresence",
            InitiatorKind = "Unknown",
            InitiatorAccount = "не определено",
            PossibleTool = assessment.Tool,
            Confidence = "Indirect",
            Area = "Cleaner Artifacts",
            Finding = $"Найден след наличия {assessment.Tool}, запуск не подтверждён",
            Details =
                $"{CleanerEvidenceClassifier.DescribeSource(evidence, assessment)} " +
                $"{evidence.Source}: {evidence.Summary}; {evidence.DeviceHint}. " +
                "Эта запись показывает наличие программы или пути к ней и не доказывает запуск либо очистку."
        };
    }

    private static void MergeCleanerEvidence(
        CleanupFinding existing,
        EvidenceRecord evidence,
        CleanerEvidenceAssessment assessment,
        bool probableCleanup)
    {
        if (probableCleanup)
        {
            existing.Severity = "High";
            existing.Assessment = "Suspicious";
            existing.ActionKind = "ProbableCleanup";
            existing.Confidence = "Probable";
            existing.Finding = $"Запуск {assessment.Tool} с дополнительными признаками возможной очистки";
        }
        else if (assessment.IsDirectExecution && existing.Confidence != "Probable")
        {
            existing.Confidence = "Confirmed";
        }

        var sourceDetails =
            $"{CleanerEvidenceClassifier.DescribeSource(evidence, assessment)} Источник: {evidence.Source}; {evidence.Summary}.";
        if (!existing.Details.Contains(sourceDetails, StringComparison.OrdinalIgnoreCase))
        {
            existing.Details += $" Дополнительное подтверждение: {sourceDetails}";
        }
    }

    private static InitiatorInfo InitiatorFromEvidence(EvidenceRecord evidence)
    {
        if (evidence.EventId == "PROCESS_HINT")
        {
            return CleanupAttribution.ParseEventLogInitiator(evidence.RawText);
        }

        if (!string.IsNullOrWhiteSpace(evidence.ResolvedUserName))
        {
            return new InitiatorInfo("User", evidence.ResolvedUserName, evidence.UserSid);
        }

        return InitiatorInfo.Unknown;
    }

    private static CleanupFinding ApplyAttribution(
        CleanupFinding finding,
        AuditResult result,
        DateTimeOffset eventAtUtc,
        InitiatorInfo initiator,
        string? correlatedTool,
        bool fromInitialSetup)
    {
        finding.InitiatorKind = initiator.Kind;
        finding.InitiatorAccount = initiator.Account;
        finding.PossibleTool = correlatedTool ?? (fromInitialSetup ? CleanupAttribution.ToolForSetupApi(true, null) : "не определено");
        finding.Confidence = CleanupAttribution.DetermineConfidence(finding.Assessment, initiator, correlatedTool, finding.Area);
        finding.Details = $"{finding.Details} {CleanupAttribution.BuildAttributionDetails(initiator, finding.PossibleTool, finding.Confidence)}";
        return finding;
    }

    private static CleanupFinding CreateFinding(
        DateTimeOffset? installAtUtc,
        DateTimeOffset eventAtUtc,
        string severity,
        string area,
        string finding,
        string details,
        DateTimeOffset timestampUtc)
    {
        if (OsInstallInfo.IsWithinPostInstallGrace(eventAtUtc, installAtUtc))
        {
            return CreateOsInstallFinding(timestampUtc, area, finding, details);
        }

        return new CleanupFinding
        {
            TimestampUtc = timestampUtc,
            Severity = severity,
            Assessment = "Suspicious",
            ActionKind = area switch
            {
                "SetupAPI" => "RegistryArtifact",
                "Event Logs" => "LogClearing",
                "Correlation" => "Correlation",
                _ => "Unknown"
            },
            Area = area,
            Finding = finding,
            Details = details
        };
    }

    private static CleanupFinding CreateOsInstallFinding(
        DateTimeOffset timestampUtc,
        string area,
        string finding,
        string details)
    {
        return new CleanupFinding
        {
            TimestampUtc = timestampUtc,
            Severity = "Info",
            Assessment = "OsInstall",
            ActionKind = "OsInstall",
            InitiatorKind = "System",
            InitiatorAccount = "SYSTEM (Windows Setup)",
            PossibleTool = "Windows Setup / Event Log Service",
            Confidence = "Normal",
            Area = area,
            Finding = finding,
            Details = $"{details} Windows сама выполнила это в первые {OsInstallInfo.PostInstallGraceHours} ч. после установки — не считается ручной зачисткой следов USB."
        };
    }

    private static bool IsFromInitialWindowsSetup(DateTime creationTimeUtc, DateTimeOffset? installAtUtc)
    {
        if (installAtUtc is null)
        {
            return false;
        }

        var moment = new DateTimeOffset(creationTimeUtc, TimeSpan.Zero);
        return OsInstallInfo.IsWithinPostInstallGrace(moment, installAtUtc);
    }
}
