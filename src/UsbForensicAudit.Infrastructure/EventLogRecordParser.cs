using System.Globalization;
using System.Xml.Linq;

namespace UsbForensicAudit;

internal sealed record ParsedEventLogRecord(
    string Provider,
    string Channel,
    int EventId,
    long? RecordId,
    string Computer,
    DateTimeOffset TimestampUtc,
    IReadOnlyDictionary<string, string> Fields,
    string RawXml);

internal static class EventLogRecordParser
{
    private static readonly string[] DeviceFieldNames =
    [
        "DeviceInstanceId", "DeviceInstanceID", "DeviceId", "DeviceID", "InstanceId", "InstanceID",
        "DeviceIdentifier", "DevicePath", "SymbolicName", "ParentId", "ParentIdPrefix",
        "ContainerId", "ClassDeviceGuid", "DeviceName"
    ];

    private static readonly string[] DeviceMarkers =
    [
        @"USBSTOR\", @"USB\", "VID_", "PID_", @"SCSI\", @"STORAGE\", @"SWD\", @"USB4\",
        "WPDBUSENUM", "WPD", "MTP", "PTP", "UASP", "UASPSTOR", "THUNDERBOLT", "PCIe-tunneled"
    ];

    public static bool TryParse(string xml, out ParsedEventLogRecord? parsed)
    {
        parsed = null;
        try
        {
            var root = XDocument.Parse(xml, LoadOptions.PreserveWhitespace).Root;
            var system = root?.Elements().FirstOrDefault(x => x.Name.LocalName == "System");
            if (root is null || system is null)
            {
                return false;
            }

            var provider = system.Elements().FirstOrDefault(x => x.Name.LocalName == "Provider")
                ?.Attribute("Name")?.Value ?? "";
            var channel = Value(system, "Channel");
            if (!int.TryParse(Value(system, "EventID"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventId))
            {
                return false;
            }

            long? recordId = long.TryParse(
                Value(system, "EventRecordID"),
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out var parsedRecordId)
                ? parsedRecordId
                : null;

            var timeText = system.Elements().FirstOrDefault(x => x.Name.LocalName == "TimeCreated")
                ?.Attribute("SystemTime")?.Value;
            if (!DateTimeOffset.TryParse(
                    timeText,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var timestamp))
            {
                return false;
            }

            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var data in root.Descendants().Where(x => x.Name.LocalName == "Data"))
            {
                AddField(fields, data.Attribute("Name")?.Value, data.Value);
            }

            foreach (var userData in root.Elements().Where(x => x.Name.LocalName == "UserData").Descendants())
            {
                if (!userData.HasElements)
                {
                    AddField(fields, userData.Name.LocalName, userData.Value);
                }
            }

            parsed = new ParsedEventLogRecord(
                provider,
                channel,
                eventId,
                recordId,
                Value(system, "Computer"),
                timestamp.ToUniversalTime(),
                fields,
                xml);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static EvidenceRecord? ToEvidence(ParsedEventLogRecord parsed, string formattedMessage = "")
    {
        if (!EventLogEventClassifier.IsRelevant(parsed))
        {
            return null;
        }

        var deviceHint = ExtractDeviceHint(parsed.Fields, formattedMessage);
        var summary = BuildSummary(parsed, deviceHint, formattedMessage);
        return new EvidenceRecord
        {
            TimestampUtc = parsed.TimestampUtc,
            Source = string.IsNullOrWhiteSpace(parsed.Provider)
                ? parsed.Channel
                : $"{parsed.Channel}/{parsed.Provider}",
            Provider = parsed.Provider,
            Channel = parsed.Channel,
            RecordId = parsed.RecordId,
            Computer = parsed.Computer,
            SourceRecord = parsed.RecordId?.ToString(CultureInfo.InvariantCulture) ?? "",
            EvidenceCategory = EventLogEventClassifier.Classify(parsed),
            UserExplanation = EventLogEventClassifier.Explain(parsed),
            EventId = parsed.EventId.ToString(CultureInfo.InvariantCulture),
            Level = parsed.Fields.TryGetValue("Level", out var level) ? level : "",
            DeviceHint = deviceHint,
            Summary = summary,
            RawText = parsed.RawXml
        };
    }

    internal static bool ContainsDeviceMarker(string value)
    {
        return !string.IsNullOrWhiteSpace(value)
               && DeviceMarkers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static string ExtractDeviceHint(IReadOnlyDictionary<string, string> fields, string fallback)
    {
        foreach (var name in DeviceFieldNames)
        {
            if (fields.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return Truncate(value.Trim(), 500);
            }
        }

        foreach (var value in fields.Values)
        {
            var hint = ExtractMarkedText(value);
            if (hint.Length > 0)
            {
                return hint;
            }
        }

        return ExtractMarkedText(fallback);
    }

    private static string ExtractMarkedText(string value)
    {
        var match = DeviceMarkers
            .Select(marker => (Marker: marker, Index: value.IndexOf(marker, StringComparison.OrdinalIgnoreCase)))
            .Where(x => x.Index >= 0)
            .OrderBy(x => x.Index)
            .FirstOrDefault();
        if (match.Index < 0 || string.IsNullOrWhiteSpace(match.Marker))
        {
            return "";
        }

        return Truncate(value[match.Index..].ReplaceLineEndings(" ").Trim(), 500);
    }

    private static string BuildSummary(ParsedEventLogRecord parsed, string deviceHint, string formattedMessage)
    {
        if (deviceHint.Length > 0)
        {
            return Truncate($"{parsed.Provider} {parsed.EventId}: {deviceHint}", 800);
        }

        var namedFields = string.Join(
            "; ",
            parsed.Fields.Where(x => !string.IsNullOrWhiteSpace(x.Value)).Take(4).Select(x => $"{x.Key}={x.Value}"));
        if (namedFields.Length > 0)
        {
            return Truncate($"{parsed.Provider} {parsed.EventId}: {namedFields}", 800);
        }

        var firstLine = formattedMessage.Split(["\r\n", "\n"], StringSplitOptions.None).FirstOrDefault() ?? "";
        return Truncate(firstLine.Length > 0 ? firstLine : $"{parsed.Provider} Event {parsed.EventId}", 800);
    }

    private static string Value(XElement parent, string localName)
    {
        return parent.Elements().FirstOrDefault(x => x.Name.LocalName == localName)?.Value ?? "";
    }

    private static void AddField(IDictionary<string, string> fields, string? name, string value)
    {
        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (!fields.TryAdd(name, value.Trim()))
        {
            for (var index = 2; ; index++)
            {
                if (fields.TryAdd($"{name}#{index}", value.Trim()))
                {
                    break;
                }
            }
        }
    }

    private static string Truncate(string value, int length) => value.Length <= length ? value : value[..length];
}

internal static class EventLogEventClassifier
{
    public static bool IsRelevant(ParsedEventLogRecord record)
    {
        if (Is(record, "Microsoft-Windows-Eventlog", 104)
            || Is(record, "Microsoft-Windows-Security-Auditing", 1102)
            || Is(record, "Microsoft-Windows-Security-Auditing", 6416))
        {
            return true;
        }

        if (IsProvider(record, "Microsoft-Windows-Storage-ClassPnP")
            || IsProvider(record, "Microsoft-Windows-Partition")
            || IsProvider(record, "Microsoft-Windows-WPD-MTPClassDriver"))
        {
            return IsProvider(record, "Microsoft-Windows-WPD-MTPClassDriver")
                   || record.Fields.Values.Any(EventLogRecordParser.ContainsDeviceMarker);
        }

        return record.Fields.Values.Any(EventLogRecordParser.ContainsDeviceMarker);
    }

    public static string Classify(ParsedEventLogRecord record)
    {
        if (Is(record, "Microsoft-Windows-Eventlog", 104)
            || Is(record, "Microsoft-Windows-Security-Auditing", 1102))
        {
            return "Очистка журнала";
        }

        if (Is(record, "Microsoft-Windows-Security-Auditing", 6416))
        {
            return "Подключение/распознавание устройства";
        }

        if (IsProvider(record, "Microsoft-Windows-Partition") && record.EventId == 1006)
        {
            return "Подключение/инициализация устройства";
        }

        if (IsProvider(record, "Microsoft-Windows-Storage-ClassPnP"))
        {
            return record.EventId is 510 or 511 or 512
                ? "Отключение/удаление устройства"
                : "Подключение/инициализация устройства";
        }

        if (IsProvider(record, "Microsoft-Windows-WPD-MTPClassDriver"))
        {
            return "Подключение/инициализация MTP-устройства";
        }

        return "Подключение/инициализация устройства";
    }

    public static string Explain(ParsedEventLogRecord record)
    {
        if (Is(record, "Microsoft-Windows-Eventlog", 104)
            || Is(record, "Microsoft-Windows-Security-Auditing", 1102))
        {
            return "Событие очистки журнала Windows. Это прямой индикатор возможной зачистки следов.";
        }

        if (Is(record, "Microsoft-Windows-Security-Auditing", 6416))
        {
            return "Security Audit PNP Activity: Windows распознала новое внешнее устройство. Доступно только если включен аудит PnP.";
        }

        return "Структурированное событие Windows, связанное с PnP, накопителем, разделом, MTP или драйвером устройства.";
    }

    private static bool Is(ParsedEventLogRecord record, string provider, int eventId)
        => IsProvider(record, provider) && record.EventId == eventId;

    private static bool IsProvider(ParsedEventLogRecord record, string provider)
        => record.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase);
}

internal static class EventLogRetentionPolicy
{
    public static void AddCapWarning(ICollection<string> warnings, string source, int cap)
    {
        warnings.Add($"Журнал {source}: достигнут лимит {cap}; более старые события не загружены.");
    }
}
