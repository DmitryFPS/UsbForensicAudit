namespace UsbForensicAudit;

public static class UsbOblivionAttributionAnalyzer
{
    public static void Analyze(AuditResult result, List<CleanupFinding> findings)
    {
        var oblivionLaunches = result.Evidence
            .Where(IsOblivionEvidence)
            .OrderByDescending(x => x.TimestampUtc)
            .ToArray();

        if (oblivionLaunches.Length == 0)
        {
            return;
        }

        var usbStorCount = result.Devices.Count(x => x.Source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase));
        var setupApiUsb = result.Evidence.Count(x =>
            x.Source.Contains("setupapi", StringComparison.OrdinalIgnoreCase)
            && (x.Summary.Contains("USB", StringComparison.OrdinalIgnoreCase)
                || x.DeviceHint.Contains("USB", StringComparison.OrdinalIgnoreCase)));
        var registryUsb = result.Devices.Count(x =>
            x.Source.Equals("Registry: USB", StringComparison.OrdinalIgnoreCase)
            || x.Source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase));

        var hasRegistryGap = usbStorCount > 0 && setupApiUsb == 0;
        var hasMountedWithoutUsb = result.Devices.Any(x => x.Source.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase))
                                   && registryUsb == 0;
        var knownFindings = result.CleanupFindings.Concat(findings).ToArray();
        var setupApiMissing = knownFindings.Any(x =>
            x.Finding.Contains("setupapi.dev.log отсутствует", StringComparison.OrdinalIgnoreCase));
        var setupApiSmall = knownFindings.Any(x =>
            x.Finding.Contains("setupapi.dev.log подозрительно мал", StringComparison.OrdinalIgnoreCase)
            || x.Finding.Contains("пересоздан", StringComparison.OrdinalIgnoreCase));

        foreach (var launch in oblivionLaunches.Take(10))
        {
            var assessment = CleanerEvidenceClassifier.Analyze(launch)!;
            var correlatedLogClear = result.Evidence.Any(x =>
                x.EventId is "104" or "1102"
                && Math.Abs((x.TimestampUtc - launch.TimestampUtc).TotalHours) <= 2);
            var correlatedRegistryIssue = result.CleanupFindings.Concat(findings).Any(x =>
                x.Area is "SetupAPI" or "Correlation"
                && x.Assessment == "Suspicious"
                && Math.Abs((x.TimestampUtc - launch.TimestampUtc).TotalHours) <= 24);
            var explicitRemovalIntent = CleanerEvidenceClassifier.HasExplicitRemovalIntent(launch, assessment);

            var probableCleanup = explicitRemovalIntent || correlatedRegistryIssue || correlatedLogClear;
            var details = BuildDetails(
                launch,
                probableCleanup,
                explicitRemovalIntent,
                correlatedRegistryIssue,
                hasRegistryGap,
                hasMountedWithoutUsb,
                setupApiMissing,
                setupApiSmall,
                correlatedLogClear,
                usbStorCount,
                setupApiUsb);
            var existing = findings.FirstOrDefault(x =>
                x.PossibleTool.Contains("Oblivion", StringComparison.OrdinalIgnoreCase)
                && x.ActionKind is "ToolLaunch" or "ProbableCleanup"
                && Math.Abs((x.TimestampUtc - launch.TimestampUtc).TotalMinutes) <= 5);
            if (existing is not null)
            {
                if (probableCleanup)
                {
                    existing.Severity = "High";
                    existing.Assessment = "Suspicious";
                    existing.ActionKind = "ProbableCleanup";
                    existing.Confidence = "Probable";
                    existing.Area = "USB Oblivion";
                    existing.Finding = "USB Oblivion: запуск с дополнительными признаками возможной очистки";
                }

                if (!existing.Details.Contains("Специальная проверка USB Oblivion", StringComparison.OrdinalIgnoreCase))
                {
                    existing.Details += $" Специальная проверка USB Oblivion: {details}";
                }

                continue;
            }

            findings.Add(new CleanupFinding
            {
                TimestampUtc = launch.TimestampUtc,
                Severity = probableCleanup ? "High" : "Medium",
                Assessment = "Suspicious",
                ActionKind = probableCleanup ? "ProbableCleanup" : "ToolLaunch",
                InitiatorKind = "Unknown",
                InitiatorAccount = "не определено",
                PossibleTool = "USB Oblivion",
                Confidence = probableCleanup ? "Probable" : assessment.IsDirectExecution ? "Confirmed" : "Probable",
                Area = probableCleanup ? "USB Oblivion" : "Cleaner Artifacts",
                Finding = probableCleanup
                    ? "USB Oblivion: запуск с дополнительными признаками возможной очистки"
                    : "USB Oblivion: зафиксирован запуск утилиты удаления следов",
                Details = details
            });
        }
    }

    private static bool IsOblivionEvidence(EvidenceRecord evidence)
    {
        var assessment = CleanerEvidenceClassifier.Analyze(evidence);
        return assessment?.SupportsExecution == true
               && CleanerToolCatalog.IsOblivionTool(assessment.Tool);
    }

    private static string BuildDetails(
        EvidenceRecord launch,
        bool probableCleanup,
        bool explicitRemovalIntent,
        bool correlatedRegistryIssue,
        bool hasRegistryGap,
        bool hasMountedWithoutUsb,
        bool setupApiMissing,
        bool setupApiSmall,
        bool correlatedLogClear,
        int usbStorCount,
        int setupApiUsb)
    {
        var parts = new List<string>
        {
            $"{launch.Source}: {launch.Summary}"
        };

        if (probableCleanup)
        {
            if (explicitRemovalIntent)
            {
                parts.Add("В командной строке найдены параметры реальной очистки (-enable) или иная явная команда удаления. Это подтверждает намерение, но не успешное завершение.");
            }

            if (correlatedRegistryIssue)
            {
                parts.Add("В пределах 24 часов найден независимый подозрительный признак в SetupAPI или реестре USB.");
            }

            if (hasRegistryGap)
            {
                parts.Add($"В реестре USBSTOR: {usbStorCount}, в setupapi.dev.log USB-записей: {setupApiUsb}.");
            }

            if (hasMountedWithoutUsb)
            {
                parts.Add("Найдены MountedDevices при отсутствии соответствующих USB-записей.");
            }

            if (setupApiMissing)
            {
                parts.Add("setupapi.dev.log отсутствует или пересоздан.");
            }

            if (setupApiSmall)
            {
                parts.Add("setupapi.dev.log подозрительно мал или недавно пересоздан.");
            }

            if (correlatedLogClear)
            {
                parts.Add("Рядом по времени найдена очистка журналов Windows (104/1102).");
            }
        }
        else
        {
            parts.Add("Запуск USB Oblivion подтверждён, но фактическое удаление не установлено. Без параметра -enable программа могла работать в тестовом режиме.");
            if (hasRegistryGap || hasMountedWithoutUsb || setupApiMissing || setupApiSmall)
            {
                parts.Add("Текущее состояние содержит отдельные расхождения, но они не привязаны ко времени запуска достаточно точно для вывода о причинной связи.");
            }
        }

        parts.Add(CleanupAttribution.BuildAttributionDetails(
            InitiatorInfo.Unknown,
            "USB Oblivion",
            probableCleanup ? "Probable" : "Indirect"));

        return string.Join(" ", parts);
    }
}
