using System.Diagnostics.Eventing.Reader;

namespace UsbForensicAudit;

public sealed class ProcessAttributionCollector
{
    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings, int maxEvents = 400)
    {
        var results = new List<EvidenceRecord>();

        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[EventID=4688]]")
            {
                ReverseDirection = true
            };

            using var reader = new EventLogReader(query);
            var read = 0;
            for (var record = reader.ReadEvent(); record is not null && read < maxEvents; record = reader.ReadEvent())
            {
                using (record)
                {
                    var xml = SafeXml(record);
                    var processPath = CleanupAttribution.ExtractProcessPath(xml);
                    var toolPattern = CleanerToolCatalog.Match(processPath) ?? CleanerToolCatalog.Match(xml);
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
                        EvidenceCategory = "Запуск процесса",
                        UserExplanation = "Security Audit Process Creation: процесс, который мог очистить журналы или USB-следы.",
                        EventId = "PROCESS_HINT",
                        Level = record.LevelDisplayName ?? "",
                        DeviceHint = processPath,
                        Summary = CleanerToolCatalog.DisplayName(toolPattern),
                        RawText = xml
                    });
                    read++;
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Security Event ID 4688 недоступен: {ex.Message}");
        }

        return results;
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
