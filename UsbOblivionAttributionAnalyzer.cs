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
        var setupApiMissing = result.CleanupFindings.Any(x =>
            x.Finding.Contains("setupapi.dev.log отсутствует", StringComparison.OrdinalIgnoreCase));
        var setupApiSmall = result.CleanupFindings.Any(x =>
            x.Finding.Contains("setupapi.dev.log подозрительно мал", StringComparison.OrdinalIgnoreCase)
            || x.Finding.Contains("пересоздан", StringComparison.OrdinalIgnoreCase));

        foreach (var launch in oblivionLaunches.Take(10))
        {
            var correlatedLogClear = result.Evidence.Any(x =>
                x.EventId is "104" or "1102"
                && Math.Abs((x.TimestampUtc - launch.TimestampUtc).TotalHours) <= 2);

            var probableCleanup = hasRegistryGap || hasMountedWithoutUsb || setupApiMissing || setupApiSmall || correlatedLogClear;
            findings.Add(new CleanupFinding
            {
                TimestampUtc = launch.TimestampUtc,
                Severity = probableCleanup ? "High" : "Medium",
                Assessment = "Suspicious",
                ActionKind = probableCleanup ? "ProbableCleanup" : "ToolLaunch",
                InitiatorKind = "Unknown",
                InitiatorAccount = "не определено",
                PossibleTool = "USB Oblivion",
                Confidence = probableCleanup ? "Probable" : "Indirect",
                Area = probableCleanup ? "USB Oblivion" : "Cleaner Artifacts",
                Finding = probableCleanup
                    ? "USB Oblivion: вероятно выполнено удаление следов USB"
                    : "USB Oblivion: зафиксирован запуск утилиты удаления следов",
                Details = BuildDetails(launch, probableCleanup, hasRegistryGap, setupApiMissing, setupApiSmall, correlatedLogClear, usbStorCount, setupApiUsb)
            });
        }

        if ((hasRegistryGap || setupApiMissing) && oblivionLaunches.Length > 0)
        {
            var latest = oblivionLaunches[0].TimestampUtc;
            if (!findings.Any(x =>
                    x.PossibleTool.Contains("Oblivion", StringComparison.OrdinalIgnoreCase)
                    && x.ActionKind == "ProbableCleanup"
                    && Math.Abs((x.TimestampUtc - latest).TotalMinutes) < 5))
            {
                findings.Add(new CleanupFinding
                {
                    TimestampUtc = latest,
                    Severity = "High",
                    Assessment = "Suspicious",
                    ActionKind = "ProbableCleanup",
                    InitiatorKind = "Unknown",
                    InitiatorAccount = "не определено",
                    PossibleTool = "USB Oblivion",
                    Confidence = "Probable",
                    Area = "USB Oblivion",
                    Finding = "Противоречие реестра USB и журналов после запуска USB Oblivion",
                    Details =
                        $"USBSTOR в реестре: {usbStorCount}; релевантных USB-записей в setupapi: {setupApiUsb}. " +
                        "Сочетание похоже на удаление или пересоздание следов USB. " +
                        CleanupAttribution.BuildAttributionDetails(InitiatorInfo.Unknown, "USB Oblivion", "Probable")
                });
            }
        }
    }

    private static bool IsOblivionEvidence(EvidenceRecord evidence)
    {
        if (evidence.EventId == "PROCESS_HINT")
        {
            return CleanerToolCatalog.IsOblivionTool(evidence.Summary)
                   || CleanerToolCatalog.IsOblivionTool(evidence.DeviceHint)
                   || CleanerToolCatalog.IsOblivionTool(evidence.RawText);
        }

        if (evidence.EventId != "CLEANER_HINT")
        {
            return false;
        }

        return CleanerToolCatalog.IsOblivionTool(evidence.Summary)
               || CleanerToolCatalog.IsOblivionTool(evidence.DeviceHint)
               || CleanerToolCatalog.IsOblivionTool(evidence.RawText);
    }

    private static string BuildDetails(
        EvidenceRecord launch,
        bool probableCleanup,
        bool hasRegistryGap,
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
            if (hasRegistryGap)
            {
                parts.Add($"В реестре USBSTOR: {usbStorCount}, в setupapi.dev.log USB-записей: {setupApiUsb}.");
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
            parts.Add("Запуск USB Oblivion сам по себе не доказывает удаление — нужны противоречия в реестре и журналах.");
        }

        parts.Add(CleanupAttribution.BuildAttributionDetails(
            InitiatorInfo.Unknown,
            "USB Oblivion",
            probableCleanup ? "Probable" : "Indirect"));

        return string.Join(" ", parts);
    }
}
