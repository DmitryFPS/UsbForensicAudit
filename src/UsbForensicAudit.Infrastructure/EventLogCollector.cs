using System.Diagnostics.Eventing.Reader;

namespace UsbForensicAudit;

public sealed class EventLogCollector
{
    private static readonly string[] Logs =
    [
        "System",
        "Security",
        "Microsoft-Windows-DeviceSetupManager/Admin",
        "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
    ];

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings, int maxPerLog = 500)
    {
        var results = new List<EvidenceRecord>();

        foreach (var logName in Logs)
        {
            try
            {
                ReadLog(logName, results, maxPerLog);
            }
            catch (Exception ex)
            {
                warnings.Add($"Журнал {logName} недоступен: {ex.Message}");
            }
        }

        return results;
    }

    private static void ReadLog(string logName, List<EvidenceRecord> results, int maxPerLog)
    {
        var query = new EventLogQuery(logName, PathType.LogName, "*[System[(EventID=104 or EventID=1102 or EventID=6416 or EventID=20001 or EventID=20003 or EventID=20006 or EventID=2100 or EventID=2101 or EventID=2102 or EventID=2105 or EventID=400 or EventID=410 or EventID=411 or EventID=420 or EventID=430 or EventID=1006 or EventID=1008)]]")
        {
            ReverseDirection = true
        };

        using var reader = new EventLogReader(query);
        var read = 0;
        for (var record = reader.ReadEvent(); record is not null && read < maxPerLog; record = reader.ReadEvent())
        {
            using (record)
            {
                var message = SafeFormat(record);
                if (!IsRelevant(record, message))
                {
                    continue;
                }

                var rawText = record.Id is 104 or 1102 ? SafeXml(record) : message;

                results.Add(new EvidenceRecord
                {
                    TimestampUtc = record.TimeCreated.HasValue ? new DateTimeOffset(record.TimeCreated.Value).ToUniversalTime() : DateTimeOffset.UtcNow,
                    Source = string.IsNullOrWhiteSpace(record.ProviderName) ? logName : $"{logName}/{record.ProviderName}",
                    EvidenceCategory = ClassifyEvent(record.Id, message),
                    UserExplanation = ExplainEvent(record.Id, message),
                    EventId = record.Id.ToString(),
                    Level = record.LevelDisplayName ?? "",
                    DeviceHint = ExtractDeviceHint(message),
                    Summary = FirstLine(message),
                    RawText = rawText
                });

                read++;
            }
        }
    }

    private static bool IsRelevant(EventRecord record, string message)
    {
        if (record.Id is 104 or 1102 or 6416 or 20001 or 20003 or 20006 or 2100 or 2101 or 2102 or 2105)
        {
            return true;
        }

        return message.Contains("USB", StringComparison.OrdinalIgnoreCase)
               || message.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
               || message.Contains("VID_", StringComparison.OrdinalIgnoreCase)
               || message.Contains("disk", StringComparison.OrdinalIgnoreCase)
               || message.Contains("device", StringComparison.OrdinalIgnoreCase);
    }

    private static string SafeFormat(EventRecord record)
    {
        try
        {
            return record.FormatDescription() ?? "";
        }
        catch
        {
            return string.Join(" | ", record.Properties.Select(x => x.Value?.ToString()).Where(x => !string.IsNullOrWhiteSpace(x)));
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
            return SafeFormat(record);
        }
    }

    private static string FirstLine(string text)
    {
        var line = text.Split(["\r\n", "\n"], StringSplitOptions.None).FirstOrDefault() ?? "";
        return line.Length > 240 ? line[..240] : line;
    }

    private static string ExtractDeviceHint(string message)
    {
        var markers = new[] { "USBSTOR", @"USB\", "VID_", "WPDBUSENUM" };
        foreach (var marker in markers)
        {
            var index = message.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                var hint = message[index..].ReplaceLineEndings(" ");
                return hint.Length > 180 ? hint[..180] : hint;
            }
        }

        return "";
    }

    private static string ClassifyEvent(int eventId, string message)
    {
        if (eventId is 104 or 1102)
        {
            return "Очистка журнала";
        }

        if (eventId == 6416)
        {
            return "Подключение/распознавание устройства";
        }

        if (LooksLikeDisconnect(message))
        {
            return "Отключение/удаление устройства";
        }

        if (LooksLikeConnect(message) || eventId is 20001 or 20003 or 20006 or 2100 or 2101 or 2102 or 2105)
        {
            return "Подключение/инициализация устройства";
        }

        return "Системное событие устройства";
    }

    private static string ExplainEvent(int eventId, string message)
    {
        if (eventId == 6416)
        {
            return "Security Audit PNP Activity: Windows распознала новое внешнее устройство. Доступно только если включен аудит PnP.";
        }

        if (eventId is 104 or 1102)
        {
            return "Событие очистки журнала Windows. Это прямой индикатор возможной зачистки следов.";
        }

        if (LooksLikeDisconnect(message))
        {
            return "Событие похоже на отключение, удаление или остановку устройства. Точность зависит от текста события конкретной сборки Windows.";
        }

        return "Событие Windows Event Log, связанное с установкой, запуском драйвера или PnP-состоянием устройства.";
    }

    private static bool LooksLikeConnect(string message)
    {
        return message.Contains("connected", StringComparison.OrdinalIgnoreCase)
               || message.Contains("started", StringComparison.OrdinalIgnoreCase)
               || message.Contains("configured", StringComparison.OrdinalIgnoreCase)
               || message.Contains("recognized", StringComparison.OrdinalIgnoreCase)
               || message.Contains("подключ", StringComparison.OrdinalIgnoreCase)
               || message.Contains("запущ", StringComparison.OrdinalIgnoreCase)
               || message.Contains("распознан", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeDisconnect(string message)
    {
        return message.Contains("disconnect", StringComparison.OrdinalIgnoreCase)
               || message.Contains("removed", StringComparison.OrdinalIgnoreCase)
               || message.Contains("stopped", StringComparison.OrdinalIgnoreCase)
               || message.Contains("surprise removal", StringComparison.OrdinalIgnoreCase)
               || message.Contains("отключ", StringComparison.OrdinalIgnoreCase)
               || message.Contains("удален", StringComparison.OrdinalIgnoreCase)
               || message.Contains("останов", StringComparison.OrdinalIgnoreCase);
    }
}
