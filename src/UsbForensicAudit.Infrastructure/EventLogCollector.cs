using System.Diagnostics.Eventing.Reader;

namespace UsbForensicAudit;

public sealed class EventLogCollector : IEvidenceCollector
{
    private sealed record ChannelDefinition(
        string Channel,
        string Provider,
        int[] EventIds,
        bool Optional = true);

    private static readonly ChannelDefinition[] Definitions =
    [
        new("System", "Microsoft-Windows-Eventlog", [104], false),
        new("System", "Microsoft-Windows-UserPnp", [20001, 20003, 20006]),
        new("System", "Microsoft-Windows-Kernel-PnP", [400, 410, 411, 420, 430]),
        new("Security", "Microsoft-Windows-Security-Auditing", [1102, 6416], false),
        new("Microsoft-Windows-Kernel-PnP/Configuration", "Microsoft-Windows-Kernel-PnP", [400, 410, 411, 420, 430]),
        new("Microsoft-Windows-Kernel-PnP/Device Configuration", "Microsoft-Windows-Kernel-PnP", [400, 410, 411, 420, 430]),
        new("Microsoft-Windows-Storage-ClassPnP/Operational", "Microsoft-Windows-Storage-ClassPnP", [507, 510, 511, 512]),
        new("Microsoft-Windows-Partition/Diagnostic", "Microsoft-Windows-Partition", [1006]),
        new("Microsoft-Windows-WPD-MTPClassDriver/Operational", "Microsoft-Windows-WPD-MTPClassDriver", []),
        new("Microsoft-Windows-DeviceSetupManager/Admin", "Microsoft-Windows-DeviceSetupManager", [100, 101, 112, 131, 200, 201, 202]),
        new("Microsoft-Windows-DeviceSetupManager/Operational", "Microsoft-Windows-DeviceSetupManager", [100, 101, 112, 131, 200, 201, 202]),
        new("Microsoft-Windows-DriverFrameworks-UserMode/Admin", "Microsoft-Windows-DriverFrameworks-UserMode", [2003, 2004, 2005, 2006, 2100, 2101, 2102, 2105]),
        new("Microsoft-Windows-DriverFrameworks-UserMode/Operational", "Microsoft-Windows-DriverFrameworks-UserMode", [2003, 2004, 2005, 2006, 2100, 2101, 2102, 2105])
    ];

    public string ProgressMessage => "Чтение Windows Event Logs...";

    public bool ShouldRun => true;

    IReadOnlyList<EvidenceRecord> IEvidenceCollector.Collect(List<string> warnings) => Collect(warnings);

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings, int maxPerChannel = 5000)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxPerChannel, 1);
        var results = new List<EvidenceRecord>();

        foreach (var state in ReadChannelStates())
        {
            results.Add(ToEvidence(state));
            if (!state.Exists || !state.IsEnabled || !string.IsNullOrEmpty(state.Error))
            {
                warnings.Add(state.Describe());
            }
        }

        foreach (var definition in Definitions)
        {
            try
            {
                ReadLog(definition, results, warnings, maxPerChannel);
            }
            catch (EventLogNotFoundException) when (definition.Optional)
            {
                // Optional analytic/operational channels differ between Windows versions and editions.
            }
            catch (Exception ex)
            {
                warnings.Add($"Журнал {definition.Channel} ({definition.Provider}) недоступен: {ex.Message}");
            }
        }

        return results;
    }

    /// <summary>
    /// Состояние каждого канала выясняется до чтения событий: пустой результат
    /// по выключенному или переполненному каналу и пустой результат по исправному
    /// каналу означают разное, и в отчёте это должно быть видно.
    /// </summary>
    internal static IReadOnlyList<EventChannelState> ReadChannelStates() =>
        ReadChannelStates(Definitions.Select(x => x.Channel));

    internal static IReadOnlyList<EventChannelState> ReadChannelStates(IEnumerable<string> channels)
    {
        var states = new List<EventChannelState>();
        foreach (var channel in channels.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var state = new EventChannelState { Channel = channel };
            try
            {
                using var configuration = new EventLogConfiguration(channel);
                state.Exists = true;
                state.IsEnabled = configuration.IsEnabled;
                state.MaximumSizeBytes = (long)configuration.MaximumSizeInBytes;

                using var session = new EventLogSession();
                var information = session.GetLogInformation(channel, PathType.LogName);
                state.FileSizeBytes = (long)(information.FileSize ?? 0);
                state.RecordCount = (long)(information.RecordCount ?? 0);
                state.OldestRecordUtc = ReadOldestRecordTime(channel);
            }
            catch (EventLogNotFoundException)
            {
                state.Exists = false;
            }
            catch (Exception ex)
            {
                state.Error = ex.Message;
            }

            states.Add(state);
        }

        return states;
    }

    /// <summary>
    /// Всё, что произошло раньше самой ранней сохранившейся записи, из канала уже
    /// вытеснено: искать там события подключения бесполезно.
    /// </summary>
    private static DateTimeOffset? ReadOldestRecordTime(string channel)
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName));
            using var record = reader.ReadEvent();
            return record?.TimeCreated is { } created
                ? new DateTimeOffset(created.ToUniversalTime(), TimeSpan.Zero)
                : null;
        }
        catch
        {
            return null;
        }
    }

    internal static EvidenceRecord ToEvidence(EventChannelState state) => new()
    {
        TimestampUtc = state.OldestRecordUtc ?? DateTimeOffset.UtcNow,
        Source = "Состояние журнала Windows",
        Provider = state.Channel,
        Channel = state.Channel,
        EvidenceCategory = "Полнота источника",
        EvidenceStrength = "Context",
        Confidence = "High",
        CanEstablishConnectionDate = false,
        Summary = state.Describe(),
        UserExplanation = state.Exists && state.IsEnabled && string.IsNullOrEmpty(state.Error)
            ? "Канал работает: отсутствие события в охваченном им периоде — довод в пользу того, "
              + "что подключения не было."
            : "Канал не даёт данных: отсутствие события в нём ничего не доказывает.",
        Provenance = $"EventLogConfiguration({state.Channel})",
        RawText = $"Channel={state.Channel}\nExists={state.Exists}\nEnabled={state.IsEnabled}\n"
                  + $"RecordCount={state.RecordCount}\nFileSize={state.FileSizeBytes}\n"
                  + $"MaximumSize={state.MaximumSizeBytes}\nOldestRecordUtc={state.OldestRecordUtc:O}\n"
                  + $"Error={state.Error}"
    };

    private static void ReadLog(
        ChannelDefinition definition,
        ICollection<EvidenceRecord> results,
        ICollection<string> warnings,
        int maxPerChannel)
    {
        var query = new EventLogQuery(definition.Channel, PathType.LogName, BuildXPath(definition))
        {
            ReverseDirection = true
        };

        using var reader = new EventLogReader(query);
        var scanned = 0;
        while (scanned < maxPerChannel)
        {
            using var record = reader.ReadEvent();
            if (record is null)
            {
                return;
            }

            scanned++;
            var xml = SafeXml(record);
            if (!EventLogRecordParser.TryParse(xml, out var parsed) || parsed is null)
            {
                continue;
            }

            var evidence = EventLogRecordParser.ToEvidence(parsed, SafeFormat(record));
            if (evidence is not null)
            {
                evidence.Level = record.LevelDisplayName ?? "";
                results.Add(evidence);
            }
        }

        EventLogRetentionPolicy.AddCapWarning(
            warnings,
            $"{definition.Channel} ({definition.Provider})",
            maxPerChannel);
    }

    private static string SafeXml(EventRecord record)
    {
        try
        {
            return record.ToXml();
        }
        catch
        {
            return "";
        }
    }

    private static string SafeFormat(EventRecord record)
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

    private static string BuildXPath(ChannelDefinition definition)
    {
        var providerClause = $"Provider[@Name='{definition.Provider}']";
        if (definition.EventIds.Length == 0)
        {
            return $"*[System[{providerClause}]]";
        }

        var ids = string.Join(" or ", definition.EventIds.Select(id => $"EventID={id}"));
        return $"*[System[{providerClause} and ({ids})]]";
    }
}
