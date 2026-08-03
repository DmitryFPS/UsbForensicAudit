namespace UsbForensicAudit;

/// <summary>
/// Сопоставляет находки аудита с техниками MITRE ATT&amp;CK. Работает поверх уже
/// готовых сигналов (устройства, признаки очистки, вынос данных), поэтому чистый
/// и тестируемый. Сопоставление намеренно консервативно: техника попадает в
/// отчёт только при наличии конкретной опоры, чтобы не завышать выводы.
/// </summary>
public static class MitreMapper
{
    public static MitreAssessment Map(AuditResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var findings = new List<MitreFinding>();

        // T1091 — использование съёмных носителей: есть хотя бы одно принесённое
        // с собой устройство-носитель.
        var mediaCount = result.Devices.Count(d => d.Externality == DeviceExternality.ExternalMedia);
        if (mediaCount > 0)
        {
            findings.Add(new MitreFinding
            {
                Technique = MitreTechnique.RemovableMediaReplication,
                EvidenceCount = mediaCount,
                Rationale = $"К машине подключались съёмные носители: {mediaCount}."
            });
        }

        // T1052.001 — вынос данных на USB: подтверждённые/вероятные признаки
        // копирования файлов с компьютера на носитель.
        var exfiltration = ExfiltrationAnalyzer.Analyze(result);
        if (exfiltration.HasFindings)
        {
            findings.Add(new MitreFinding
            {
                Technique = MitreTechnique.ExfiltrationOverUsb,
                EvidenceCount = exfiltration.OutboundCount,
                Rationale = $"Признаки выноса файлов на носитель: {exfiltration.OutboundCount} "
                            + $"(подтверждено журналом: {exfiltration.ConfirmedCount})."
            });
        }

        // T1070 / T1070.001 — удаление следов: подозрительные признаки очистки,
        // отдельно выделяется очистка журналов событий.
        var suspiciousCleanup = result.CleanupFindings.Where(x => x.IsSuspicious).ToArray();
        if (suspiciousCleanup.Length > 0)
        {
            findings.Add(new MitreFinding
            {
                Technique = MitreTechnique.IndicatorRemoval,
                EvidenceCount = suspiciousCleanup.Length,
                Rationale = $"Подозрительные признаки очистки следов: {suspiciousCleanup.Length}."
            });

            var logClearing = suspiciousCleanup.Count(MentionsEventLogClearing);
            if (logClearing > 0)
            {
                findings.Add(new MitreFinding
                {
                    Technique = MitreTechnique.ClearWindowsEventLogs,
                    EvidenceCount = logClearing,
                    Rationale = $"Признаки очистки журналов событий Windows: {logClearing} (например, событие 1102)."
                });
            }
        }

        return new MitreAssessment { Findings = findings };
    }

    private static bool MentionsEventLogClearing(CleanupFinding finding)
    {
        var haystack = $"{finding.Area} {finding.Finding} {finding.Details}";
        // 1102 — очистка журнала безопасности; 104 — очистка System/прочих журналов.
        return haystack.Contains("1102", StringComparison.Ordinal)
               || haystack.Contains("журнал", StringComparison.OrdinalIgnoreCase)
               && haystack.Contains("очищ", StringComparison.OrdinalIgnoreCase);
    }
}
