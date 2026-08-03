namespace UsbForensicAudit;

/// <summary>Одно событие единой ленты времени для вкладки «Таймлайн».</summary>
public sealed class TimelineViewEntry
{
    public required DateTimeOffset TimestampUtc { get; init; }
    public required string Kind { get; init; }
    public required string Source { get; init; }
    public required string Device { get; init; }
    public required string Description { get; init; }

    /// <summary>Строку стоит подсветить: подозрительная очистка или высокий риск.</summary>
    public bool IsAlarm { get; init; }

    public string TimestampText => DateDisplay.FormatMoscow(TimestampUtc);
}

/// <summary>
/// Строит единую ленту событий из результата аудита: USB-доказательства,
/// признаки очистки и сетевые связи — одной хронологией, новые сверху.
/// Аналитик мыслит временем: «в 14:02 подключили флешку, в 14:05 скопировали
/// файл, в 14:07 запустили чистильщик» читается лентой, а не тремя таблицами.
/// Чистая функция — тестируется без UI.
/// </summary>
public static class TimelineViewBuilder
{
    public const string KindEvidence = "USB и активность";
    public const string KindCleanup = "Очистка следов";
    public const string KindNetwork = "Сеть";

    public static IReadOnlyList<TimelineViewEntry> Build(AuditResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var entries = new List<TimelineViewEntry>();

        foreach (var evidence in result.Evidence)
        {
            entries.Add(new TimelineViewEntry
            {
                TimestampUtc = evidence.TimestampUtc,
                Kind = KindEvidence,
                Source = evidence.SourceText,
                Device = evidence.DeviceHintText,
                Description = string.IsNullOrWhiteSpace(evidence.UserExplanation)
                    ? evidence.SummaryText
                    : evidence.UserExplanationText,
                IsAlarm = false
            });
        }

        foreach (var finding in result.CleanupFindings)
        {
            entries.Add(new TimelineViewEntry
            {
                TimestampUtc = finding.TimestampUtc,
                Kind = KindCleanup,
                Source = finding.AreaText,
                Device = finding.PossibleToolText,
                Description = string.IsNullOrWhiteSpace(finding.Details)
                    ? finding.Finding
                    : $"{finding.Finding} — {finding.Details}",
                IsAlarm = finding.IsSuspicious
            });
        }

        foreach (var connection in result.NetworkConnections)
        {
            if (connection.LastSeenUtc is not { } seen)
            {
                continue;
            }

            entries.Add(new TimelineViewEntry
            {
                TimestampUtc = seen,
                Kind = KindNetwork,
                Source = connection.KindText,
                Device = connection.NameText,
                Description = string.IsNullOrWhiteSpace(connection.Details)
                    ? $"Последняя активность связи «{connection.NameText}»"
                    : connection.Details,
                IsAlarm = false
            });
        }

        return entries
            .OrderByDescending(x => x.TimestampUtc)
            .ToArray();
    }

    /// <summary>Категории событий ленты в порядке показа в фильтре.</summary>
    public static IReadOnlyList<string> Kinds { get; } = [KindEvidence, KindCleanup, KindNetwork];

    /// <summary>
    /// Устройства для фильтра: непустые упоминания, по алфавиту, без дублей.
    /// </summary>
    public static IReadOnlyList<string> Devices(IEnumerable<TimelineViewEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        return entries
            .Select(x => x.Device)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>Единый предикат фильтрации ленты — тот же для UI и тестов.</summary>
    public static bool Matches(TimelineViewEntry entry, string? kind, string? device, string? search)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (!string.IsNullOrEmpty(kind) && !entry.Kind.Equals(kind, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(device)
            && !entry.Device.Contains(device, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(search))
        {
            var haystack = $"{entry.Device} {entry.Source} {entry.Description}";
            if (!haystack.Contains(search.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }
}
