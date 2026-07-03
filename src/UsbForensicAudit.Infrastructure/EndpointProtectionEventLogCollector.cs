using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public sealed class EndpointProtectionEventLogCollector
{
    // Внутренние имена провайдеров из журнала Windows Application — в интерфейсе не показываются.
    private static readonly string[] EventProviders = ["Secret Net", "OmsHost"];
    private static readonly Regex DriveLetterRegex = new(@"\b[A-Z]:\b", RegexOptions.Compiled);

    public const string SourcePrefix = "Журнал контроля USB";
    public const string CategoryConnect = EndpointProtectionCategories.Connect;
    public const string CategoryDisconnect = EndpointProtectionCategories.Disconnect;
    public const string CategoryDenied = "Контроль USB: доступ к устройству запрещён";
    public const string CategoryGeneric = "Контроль USB: событие устройства";

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings, int maxEvents = 400)
    {
        if (!EndpointProtectionEnvironment.IsInstalled)
        {
            return [];
        }

        var results = new List<EvidenceRecord>();

        foreach (var provider in EventProviders)
        {
            try
            {
                ReadProvider(provider, results, maxEvents);
            }
            catch (Exception ex)
            {
                warnings.Add($"Журнал контроля USB ({ProviderLabel(provider)}) недоступен: {ex.Message}");
            }
        }

        return results;
    }

    private static void ReadProvider(string provider, List<EvidenceRecord> results, int maxEvents)
    {
        var query = new EventLogQuery("Application", PathType.LogName, $"*[System[Provider[@Name='{provider}']]]")
        {
            ReverseDirection = true
        };

        using var reader = new EventLogReader(query);
        var read = 0;

        for (var record = reader.ReadEvent(); record is not null && read < maxEvents; record = reader.ReadEvent())
        {
            using (record)
            {
                var message = BuildMessage(record);
                if (!IsRelevant(message))
                {
                    continue;
                }

                var category = Classify(message);
                results.Add(new EvidenceRecord
                {
                    TimestampUtc = record.TimeCreated.HasValue
                        ? new DateTimeOffset(record.TimeCreated.Value).ToUniversalTime()
                        : DateTimeOffset.UtcNow,
                    Source = $"{SourcePrefix}/{ProviderLabel(provider)}",
                    EvidenceCategory = category,
                    UserExplanation = Explain(category),
                    EventId = record.Id.ToString(),
                    Level = record.LevelDisplayName ?? "",
                    DeviceHint = ExtractDeviceHint(message),
                    Summary = FirstLine(message),
                    RawText = message
                });

                read++;
            }
        }
    }

    private static string BuildMessage(EventRecord record)
    {
        var parts = new List<string>();

        try
        {
            var formatted = record.FormatDescription();
            if (!string.IsNullOrWhiteSpace(formatted))
            {
                parts.Add(formatted);
            }
        }
        catch
        {
            // Запасной вариант — необработанные данные события.
        }

        foreach (var property in record.Properties)
        {
            var value = property?.Value?.ToString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                parts.Add(value);
            }
        }

        return string.Join(" | ", parts.Distinct(StringComparer.OrdinalIgnoreCase));
    }

    private static bool IsRelevant(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return false;
        }

        return message.Contains("USB", StringComparison.OrdinalIgnoreCase)
               || message.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
               || message.Contains("VID_", StringComparison.OrdinalIgnoreCase)
               || message.Contains("Vid_", StringComparison.OrdinalIgnoreCase)
               || message.Contains("Pid_", StringComparison.OrdinalIgnoreCase)
               || message.Contains("PID_", StringComparison.OrdinalIgnoreCase)
               || message.Contains("устройств", StringComparison.OrdinalIgnoreCase)
               || message.Contains("флеш", StringComparison.OrdinalIgnoreCase)
               || message.Contains("storage", StringComparison.OrdinalIgnoreCase)
               || message.Contains("DACS", StringComparison.OrdinalIgnoreCase)
               || message.Contains("подключ", StringComparison.OrdinalIgnoreCase)
               || message.Contains("отключ", StringComparison.OrdinalIgnoreCase)
               || message.Contains("Removable", StringComparison.OrdinalIgnoreCase)
               || DriveLetterRegex.IsMatch(message);
    }

    private static string Classify(string message)
    {
        if (LooksLikeDisconnect(message))
        {
            return CategoryDisconnect;
        }

        if (LooksLikeConnect(message))
        {
            return CategoryConnect;
        }

        if (message.Contains("запрещ", StringComparison.OrdinalIgnoreCase)
            || message.Contains("denied", StringComparison.OrdinalIgnoreCase)
            || message.Contains("blocked", StringComparison.OrdinalIgnoreCase))
        {
            return CategoryDenied;
        }

        return CategoryGeneric;
    }

    private static string Explain(string category)
    {
        return category switch
        {
            var value when value == CategoryConnect =>
                "Событие из журнала корпоративной защиты USB о подключении. При активном DLP это часто единственный надёжный источник даты подключения.",
            var value when value == CategoryDisconnect =>
                "Событие корпоративной защиты USB об отключении устройства. Полезно, когда журналы Windows и setupapi.dev.log пусты из-за фильтра дисков.",
            var value when value == CategoryDenied =>
                "Корпоративная защита зафиксировала попытку работы с устройством, которое политика запретила.",
            _ => "Событие корпоративной защиты USB, связанное с контролем устройств."
        };
    }

    private static string ExtractDeviceHint(string message)
    {
        foreach (var token in CompactVidPidParser.BuildMatchTokens(message))
        {
            return token;
        }

        var markers = new[] { "USBSTOR", @"USB\", "Removable", "Bus_1Cl_", "Bus_5Cl_" };
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

    private static string FirstLine(string text)
    {
        var line = text.Split(["\r\n", "\n"], StringSplitOptions.None).FirstOrDefault() ?? text;
        return line.Length > 240 ? line[..240] : line;
    }

    private static string ProviderLabel(string provider) =>
        provider.Equals("OmsHost", StringComparison.OrdinalIgnoreCase) ? "OmsHost" : "DLP";

    private static bool LooksLikeConnect(string message)
    {
        return message.Contains("connected", StringComparison.OrdinalIgnoreCase)
               || message.Contains("подключ", StringComparison.OrdinalIgnoreCase)
               || message.Contains("new device", StringComparison.OrdinalIgnoreCase)
               || message.Contains("новое устройство", StringComparison.OrdinalIgnoreCase)
               || message.Contains("DeviceConnected", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeDisconnect(string message)
    {
        return message.Contains("disconnect", StringComparison.OrdinalIgnoreCase)
               || message.Contains("disconnected", StringComparison.OrdinalIgnoreCase)
               || message.Contains("removed", StringComparison.OrdinalIgnoreCase)
               || message.Contains("deleted", StringComparison.OrdinalIgnoreCase)
               || message.Contains("отключ", StringComparison.OrdinalIgnoreCase)
               || message.Contains("удален", StringComparison.OrdinalIgnoreCase)
               || message.Contains("DeviceDisconnected", StringComparison.OrdinalIgnoreCase);
    }
}
