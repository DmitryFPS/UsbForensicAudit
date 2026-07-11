using System.IO;

namespace UsbForensicAudit;

public sealed class CleanupDetector
{
    public IReadOnlyList<CleanupFinding> Analyze(AuditResult result)
    {
        var findings = new List<CleanupFinding>();
        AnalyzeSetupApi(findings, result);
        AnalyzeEventLogEvidence(result, findings);
        AnalyzeCleanerEvidence(result, findings);
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
            finding.ActionKind = "LogClearing";

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

    private static void AnalyzeCleanerEvidence(AuditResult result, List<CleanupFinding> findings)
    {
        foreach (var evidence in result.Evidence.Where(x => x.EventId == "CLEANER_HINT"))
        {
            var tool = CleanupAttribution.DetectToolFromEvidence(evidence) ?? "не определено";
            var isUsbTool = CleanerToolCatalog.IsUsbForensicUtility(tool);
            var correlatedLogClear = result.Evidence.Any(x =>
                x.EventId is "104" or "1102"
                && Math.Abs((x.TimestampUtc - evidence.TimestampUtc).TotalHours) <= 2);
            var correlatedRegistryIssue = result.CleanupFindings.Any(x =>
                x.Area is "SetupAPI" or "Correlation"
                && x.Assessment == "Suspicious"
                && Math.Abs((x.TimestampUtc - evidence.TimestampUtc).TotalHours) <= 24);

            var probableCleanup = isUsbTool
                                  && (CleanerToolCatalog.IsOblivionTool(tool)
                                      ? correlatedRegistryIssue || correlatedLogClear
                                      : correlatedLogClear);

            findings.Add(new CleanupFinding
            {
                TimestampUtc = evidence.TimestampUtc,
                Severity = probableCleanup ? "High" : "Medium",
                Assessment = "Suspicious",
                ActionKind = probableCleanup ? "ProbableCleanup" : "ToolLaunch",
                InitiatorKind = "Unknown",
                InitiatorAccount = "не определено",
                PossibleTool = tool,
                Confidence = probableCleanup ? "Probable" : "Indirect",
                Area = "Cleaner Artifacts",
                Finding = probableCleanup
                    ? $"Вероятная очистка следов с участием {tool}"
                    : isUsbTool
                        ? $"Запуск USB-утилиты {tool}"
                        : "Найден индикатор запуска/наличия утилиты очистки",
                Details =
                    $"{evidence.Source}: {evidence.Summary}; {evidence.DeviceHint}. " +
                    (probableCleanup
                        ? "По времени рядом найдены очистка журналов или противоречия в реестре/setupapi."
                        : "Запуск утилиты сам по себе не доказывает очистку в этот момент — смотрите тип действия и уверенность.") +
                    " " +
                    CleanupAttribution.BuildAttributionDetails(InitiatorInfo.Unknown, tool, probableCleanup ? "Probable" : "Indirect")
            });
        }
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
