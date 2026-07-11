namespace UsbForensicAudit;

public enum CleanerEvidenceKind
{
    None = 0,
    Presence = 1,
    CorroboratingExecution = 2,
    DirectExecution = 3,
    LiveExecution = 4
}

public sealed record CleanerEvidenceAssessment(
    string Tool,
    CleanerEvidenceKind Kind,
    bool ExplicitCleanupCommand)
{
    public bool SupportsExecution => Kind >= CleanerEvidenceKind.CorroboratingExecution;
    public bool IsDirectExecution => Kind >= CleanerEvidenceKind.DirectExecution;
}

public static class CleanerEvidenceClassifier
{
    public static CleanerEvidenceAssessment? Analyze(EvidenceRecord evidence)
    {
        var text = string.Join(
            Environment.NewLine,
            evidence.Summary,
            evidence.DeviceHint,
            evidence.RawText,
            evidence.SourceFile,
            evidence.SourceRecord);
        var pattern = CleanerToolCatalog.MatchTrackedUtility(text);
        var explicitPattern = evidence.EventId is "PROCESS_HINT" or "LIVE_PROCESS"
            ? CleanerToolCatalog.MatchExplicitCleanupCommand(text)
            : null;
        pattern ??= explicitPattern;
        if (pattern is null)
        {
            return null;
        }

        var kind = ClassifyKind(evidence);
        if (kind == CleanerEvidenceKind.None)
        {
            return null;
        }

        return new CleanerEvidenceAssessment(
            CleanerToolCatalog.DisplayName(pattern),
            kind,
            explicitPattern is not null);
    }

    public static bool HasExplicitRemovalIntent(
        EvidenceRecord evidence,
        CleanerEvidenceAssessment assessment)
    {
        if (assessment.ExplicitCleanupCommand)
        {
            return true;
        }

        if (!CleanerToolCatalog.IsOblivionTool(assessment.Tool))
        {
            return false;
        }

        var text = string.Join(" ", evidence.RawText, evidence.Summary, evidence.DeviceHint);
        return text.Contains("-enable", StringComparison.OrdinalIgnoreCase);
    }

    public static string DescribeSource(
        EvidenceRecord evidence,
        CleanerEvidenceAssessment assessment) =>
        assessment.Kind switch
        {
            CleanerEvidenceKind.LiveExecution =>
                "Процесс работал во время сканирования.",
            CleanerEvidenceKind.DirectExecution when evidence.EventId == "PROCESS_HINT" =>
                "Security Event 4688 напрямую зафиксировал создание процесса.",
            CleanerEvidenceKind.DirectExecution when evidence.EventId == "CLEANER_EXECUTION" =>
                "Prefetch подтверждает запуск программы; время соответствует записи Prefetch.",
            CleanerEvidenceKind.DirectExecution when evidence.EventId == "CLEANER_PREFETCH_TAMPER" =>
                "Prefetch подтверждает запуск, но файл помечен read-only — возможная попытка зафиксировать или скрыть след.",
            CleanerEvidenceKind.CorroboratingExecution when evidence.EventId is "BAM_EXECUTION" or "DAM_EXECUTION" =>
                "BAM/DAM содержит время активности исполняемого файла и пользователя.",
            CleanerEvidenceKind.CorroboratingExecution when evidence.Source.Contains("UserAssist", StringComparison.OrdinalIgnoreCase) =>
                "UserAssist подтверждает взаимодействие пользователя с программой.",
            CleanerEvidenceKind.CorroboratingExecution when evidence.Source.Contains("MuiCache", StringComparison.OrdinalIgnoreCase) =>
                "MuiCache фиксирует запуск исполняемого файла через оболочку Windows.",
            CleanerEvidenceKind.CorroboratingExecution =>
                "Системный артефакт подтверждает или поддерживает факт запуска.",
            CleanerEvidenceKind.Presence when evidence.EventId == "INVENTORY_PRESENCE" =>
                "Amcache подтверждает наличие файла или программы, но не доказывает запуск.",
            CleanerEvidenceKind.Presence when evidence.EventId == "PATH_PRESENT" =>
                "Shimcache содержит путь к программе; на Windows 10/11 одна эта запись не доказывает запуск.",
            _ => "Найден связанный артефакт программы."
        };

    private static CleanerEvidenceKind ClassifyKind(EvidenceRecord evidence)
    {
        if (evidence.EventId == "LIVE_PROCESS")
        {
            return CleanerEvidenceKind.LiveExecution;
        }

        if (evidence.EventId is "PROCESS_HINT" or "CLEANER_EXECUTION" or "CLEANER_PREFETCH_TAMPER")
        {
            return CleanerEvidenceKind.DirectExecution;
        }

        if (evidence.EventId is "BAM_EXECUTION" or "DAM_EXECUTION" or "CLEANER_HINT")
        {
            return CleanerEvidenceKind.CorroboratingExecution;
        }

        if (evidence.EventId == "PCA_APPLICATION_RECORD")
        {
            return evidence.Channel.Contains("AppLaunchDic", StringComparison.OrdinalIgnoreCase)
                ? CleanerEvidenceKind.CorroboratingExecution
                : CleanerEvidenceKind.Presence;
        }

        if (evidence.Source.Contains("UserAssist", StringComparison.OrdinalIgnoreCase)
            || evidence.Source.Contains("MuiCache", StringComparison.OrdinalIgnoreCase))
        {
            return CleanerEvidenceKind.CorroboratingExecution;
        }

        if (evidence.EventId is "INVENTORY_PRESENCE" or "PATH_PRESENT")
        {
            return CleanerEvidenceKind.Presence;
        }

        return CleanerEvidenceKind.None;
    }
}
