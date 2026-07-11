using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;

namespace UsbForensicAudit;

public sealed class ProcessAttributionCollector : IEvidenceCollector
{
    public string ProgressMessage => "Поиск процессов очистки в Security (4688)...";

    public bool ShouldRun => true;

    IReadOnlyList<EvidenceRecord> IEvidenceCollector.Collect(List<string> warnings) => Collect(warnings);

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings, int maxEvents = 10_000)
    {
        var results = new List<EvidenceRecord>();
        CollectRunningProcesses(results, warnings);

        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[EventID=4688]]")
            {
                ReverseDirection = true
            };

            using var reader = new EventLogReader(query);
            var inspected = 0;
            for (var record = reader.ReadEvent(); record is not null && inspected < maxEvents; record = reader.ReadEvent())
            {
                using (record)
                {
                    inspected++;
                    var xml = SafeXml(record);
                    var processPath = CleanupAttribution.ExtractProcessPath(xml);
                    var toolPattern = CleanerToolCatalog.MatchTrackedUtility(processPath)
                                      ?? CleanerToolCatalog.MatchTrackedUtility(xml)
                                      ?? CleanerToolCatalog.MatchExplicitCleanupCommand(xml);
                    if (toolPattern is null)
                    {
                        continue;
                    }

                    results.Add(new EvidenceRecord
                    {
                        TimestampUtc = record.TimeCreated.HasValue
                            ? new DateTimeOffset(record.TimeCreated.Value).ToUniversalTime()
                            : DateTimeOffset.UtcNow,
                        Source = "Security/4688",
                        Provider = "Microsoft-Windows-Security-Auditing",
                        Channel = "Security",
                        RecordId = record.RecordId,
                        SourceRecord = record.RecordId?.ToString() ?? "",
                        EvidenceCategory = "Запуск процесса",
                        EvidenceStrength = "Direct",
                        Confidence = "High",
                        UserExplanation = "Security Event 4688 зафиксировал создание процесса. Запуск сам по себе не доказывает выполненную очистку.",
                        EventId = "PROCESS_HINT",
                        Level = record.LevelDisplayName ?? "",
                        DeviceHint = processPath,
                        Summary = CleanerToolCatalog.DisplayName(toolPattern),
                        Provenance =
                            $"Windows Event Log: channel=Security; provider=Microsoft-Windows-Security-Auditing; record={record.RecordId?.ToString() ?? "unknown"}",
                        CanEstablishConnectionDate = false,
                        RawText = xml
                    });
                }
            }

            if (inspected >= maxEvents)
            {
                warnings.Add($"Security Event ID 4688: проверены последние {maxEvents:N0} событий; более старые записи не анализировались.");
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Security Event ID 4688 недоступен: {ex.Message}");
        }

        return results;
    }

    internal static void CollectRunningProcesses(
        List<EvidenceRecord> results,
        List<string> warnings)
    {
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    try
                    {
                        var processName = process.ProcessName;
                        var path = "";
                        try
                        {
                            path = process.MainModule?.FileName ?? "";
                        }
                        catch
                        {
                            // Для защищённых процессов имя всё равно остаётся доступным.
                        }

                        var pattern = CleanerToolCatalog.MatchTrackedUtility(path)
                                      ?? CleanerToolCatalog.MatchTrackedUtility(processName);
                        if (pattern is null)
                        {
                            continue;
                        }

                        DateTimeOffset timestamp;
                        try
                        {
                            timestamp = new DateTimeOffset(process.StartTime).ToUniversalTime();
                        }
                        catch
                        {
                            timestamp = DateTimeOffset.UtcNow;
                        }

                        var displayName = CleanerToolCatalog.DisplayName(pattern);
                        results.Add(new EvidenceRecord
                        {
                            TimestampUtc = timestamp,
                            AcquisitionTimestampUtc = DateTimeOffset.UtcNow,
                            Source = "Live Process Snapshot",
                            Provider = "System.Diagnostics.Process",
                            Channel = "Live",
                            SourceRecord = process.Id.ToString(),
                            EvidenceCategory = "Запущенный процесс",
                            EvidenceStrength = "Direct",
                            Confidence = "High",
                            UserExplanation = "Процесс работал во время сканирования. Это подтверждает запуск, но не выполненную очистку.",
                            EventId = "LIVE_PROCESS",
                            DeviceHint = string.IsNullOrWhiteSpace(path) ? processName : path,
                            Summary = displayName,
                            Provenance = $"Live process snapshot: pid={process.Id}; name={processName}",
                            CanEstablishConnectionDate = false,
                            RawText = $"ProcessName={processName}; Path={path}; Pid={process.Id}"
                        });
                    }
                    catch
                    {
                        // Процесс мог завершиться между перечислением и чтением свойств.
                    }
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Снимок запущенных cleaner-процессов недоступен: {ex.Message}");
        }
    }

    private static string SafeXml(EventRecord record)
    {
        try
        {
            return record.ToXml();
        }
        catch
        {
            try
            {
                return record.FormatDescription() ?? "";
            }
            catch
            {
                return "";
            }
        }
    }
}
