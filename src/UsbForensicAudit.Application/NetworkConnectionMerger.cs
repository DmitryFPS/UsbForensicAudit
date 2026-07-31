namespace UsbForensicAudit;

/// <summary>
/// Сводит записи разных сборщиков в одну связь.
///
/// Одна и та же сеть Wi-Fi лежит и в списке профилей реестра, и в подписях
/// сетей, и в журнале службы автонастройки; один и тот же сервер называется то
/// «\\20.20.20.76\r0» в проводнике, то «\20.20.20.76» в журнале SMB. Без
/// сведения таких записей вкладка превращается в перечисление артефактов, а
/// счёт связей в отчёте становится втрое больше действительного.
/// </summary>
public static class NetworkConnectionMerger
{
    public static List<NetworkConnectionRecord> Merge(IEnumerable<NetworkConnectionRecord> collected)
    {
        var merged = new Dictionary<string, NetworkConnectionRecord>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in collected)
        {
            var key = BuildKey(record);
            record.CanonicalKey = key;
            if (!merged.TryGetValue(key, out var existing))
            {
                merged[key] = Normalize(record);
                continue;
            }

            Absorb(existing, record);
        }

        foreach (var record in merged.Values)
        {
            Finish(record);
        }

        return [.. merged.Values.OrderBy(x => NetworkConnectionKind.Rank(x.Kind))
            .ThenByDescending(x => x.LastSeenUtc ?? DateTimeOffset.MinValue)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>
    /// Ключ связи. Для сетевых папок, узлов удалённого стола и сайтов ключом
    /// служит имя узла: у одного сервера бывают десятки папок, и каждая из них —
    /// обращение внутри одной связи, а не отдельная связь. Для сетей ключ — имя
    /// профиля, для Bluetooth — адрес устройства, который не меняется.
    /// </summary>
    public static string BuildKey(NetworkConnectionRecord record)
    {
        var identity = record.Kind switch
        {
            NetworkConnectionKind.NetworkShare or NetworkConnectionKind.RemoteDesktop
                or NetworkConnectionKind.WebSite => HostIdentity(record),
            NetworkConnectionKind.Bluetooth => FirstNotEmpty(record.Address, record.Name),
            _ => FirstNotEmpty(record.Name, record.Address)
        };

        return $"{record.Kind}|{identity.Trim().ToLowerInvariant()}";
    }

    private static string HostIdentity(NetworkConnectionRecord record)
    {
        var host = NetworkTarget.HostOf(FirstNotEmpty(record.Address, record.Name));
        return host.Length > 0 ? host : FirstNotEmpty(record.Name, record.Address);
    }

    private static string FirstNotEmpty(params string[] values) =>
        values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim() ?? "";

    private static NetworkConnectionRecord Normalize(NetworkConnectionRecord record)
    {
        if (!string.IsNullOrWhiteSpace(record.Source) && !record.Sources.Contains(record.Source))
        {
            record.Sources.Add(record.Source);
        }

        return record;
    }

    /// <summary>
    /// Вливает вторую запись в первую. Поле заполняется только если пустует:
    /// сведения одного источника не должны затирать сведения другого, иначе
    /// подробное описание из реестра исчезнет под кратким из журнала.
    /// </summary>
    private static void Absorb(NetworkConnectionRecord target, NetworkConnectionRecord extra)
    {
        target.Name = Prefer(target.Name, extra.Name);
        target.Address = Prefer(target.Address, extra.Address);
        target.Security = Prefer(target.Security, extra.Security);
        target.Adapter = Prefer(target.Adapter, extra.Adapter);
        target.Account = Prefer(target.Account, extra.Account);
        target.UserSid = Prefer(target.UserSid, extra.UserSid);
        target.ResolvedUserName = Prefer(target.ResolvedUserName, extra.ResolvedUserName);

        if (target.Direction == NetworkDirection.Unknown)
        {
            target.Direction = extra.Direction;
        }

        if (extra.FirstSeenUtc is not null
            && (target.FirstSeenUtc is null || extra.FirstSeenUtc < target.FirstSeenUtc))
        {
            target.FirstSeenUtc = extra.FirstSeenUtc;
            target.FirstSeenProvenance = extra.FirstSeenProvenance;
        }

        if (extra.LastSeenUtc is not null
            && (target.LastSeenUtc is null || extra.LastSeenUtc > target.LastSeenUtc))
        {
            target.LastSeenUtc = extra.LastSeenUtc;
            target.LastSeenProvenance = extra.LastSeenProvenance;
        }

        target.Details = JoinDetails(target.Details, extra.Details);
        target.Sessions.AddRange(extra.Sessions);
        target.Visits.AddRange(extra.Visits);
        AddDistinct(target.LocalAddresses, extra.LocalAddresses);
        AddDistinct(target.Sources, extra.Sources);
        if (!string.IsNullOrWhiteSpace(extra.Source))
        {
            AddDistinct(target.Sources, [extra.Source]);
        }

        if (!string.IsNullOrWhiteSpace(extra.Provenance)
            && !target.Provenance.Contains(extra.Provenance, StringComparison.OrdinalIgnoreCase))
        {
            target.Provenance = target.Provenance.Length == 0
                ? extra.Provenance
                : $"{target.Provenance}; {extra.Provenance}";
        }
    }

    /// <summary>
    /// Убирает повторы и раскладывает записи по времени. Повторы неизбежны:
    /// подключение к сети попадает и в журнал профилей, и в журнал Wi-Fi.
    /// </summary>
    private static void Finish(NetworkConnectionRecord record)
    {
        record.Sessions = [.. record.Sessions
            .GroupBy(SessionKey)
            .Select(group => group.OrderByDescending(x => x.EndedUtc is not null).First())
            .OrderByDescending(x => x.StartedUtc ?? x.EndedUtc ?? DateTimeOffset.MinValue)];

        record.Visits = [.. record.Visits
            .GroupBy(VisitKey, StringComparer.OrdinalIgnoreCase)
            .SelectMany(CollapseSameTarget)
            .OrderBy(x => NetworkVisitKind.Rank(x.Kind))
            .ThenByDescending(x => x.WhenUtc ?? DateTimeOffset.MinValue)];

        // Даты связи не могут быть уже, чем её сеансы и обращения: сеанс из
        // журнала иногда старше самой записи профиля в реестре.
        var moments = record.Sessions.SelectMany(x => new[] { x.StartedUtc, x.EndedUtc })
            .Concat(record.Visits.Select(x => x.WhenUtc))
            .Where(x => x is not null)
            .Select(x => x!.Value)
            .ToArray();

        if (moments.Length > 0)
        {
            var earliest = moments.Min();
            var latest = moments.Max();
            if (record.FirstSeenUtc is null || earliest < record.FirstSeenUtc)
            {
                record.FirstSeenUtc = earliest;
                record.FirstSeenProvenance = FirstNotEmpty(record.FirstSeenProvenance,
                    "Взято по самому раннему сеансу или обращению");
            }

            if (record.LastSeenUtc is null || latest > record.LastSeenUtc)
            {
                record.LastSeenUtc = latest;
                record.LastSeenProvenance = FirstNotEmpty(record.LastSeenProvenance,
                    "Взято по самому позднему сеансу или обращению");
            }
        }
    }

    private static string SessionKey(NetworkSession session) =>
        $"{session.StartedUtc?.ToUnixTimeSeconds()}|{session.EndedUtc?.ToUnixTimeSeconds()}|{session.Outcome}";

    /// <summary>
    /// Один и тот же путь приходит из журнала обращений, из дерева папок
    /// проводника и из ярлыка. Время у этих следов разное, и по времени их
    /// различать нельзя: получалось три строки об одной и той же папке. В отчёте
    /// остаётся одна — с самым поздним из известных времён и с числом следов, в
    /// которых путь встретился.
    /// </summary>
    private static string VisitKey(NetworkVisit visit) =>
        $"{visit.Kind}|{visit.Target.Trim().TrimEnd('\\').ToLowerInvariant()}";

    /// <summary>
    /// Строки об одном и том же пути. У каждого пользователя остаётся своя
    /// строка: две учётные записи, открывавшие одну папку, — это два разных
    /// факта. Следы без пользователя приписываются к самой поздней строке с
    /// известным пользователем: журнал обращений к сетевым папкам ведёт ядро, и
    /// в его записях пользователя нет, но папка та же.
    /// </summary>
    private static IEnumerable<NetworkVisit> CollapseSameTarget(IEnumerable<NetworkVisit> group)
    {
        var items = group.OrderByDescending(x => x.WhenUtc ?? DateTimeOffset.MinValue).ToList();
        var named = items
            .Where(x => !string.IsNullOrWhiteSpace(x.UserSid))
            .GroupBy(x => x.UserSid, StringComparer.OrdinalIgnoreCase)
            .Select(KeepLatestMention)
            .ToList();

        var anonymousMentions = items
            .Where(x => string.IsNullOrWhiteSpace(x.UserSid))
            .Sum(x => x.MentionCount ?? 1);

        if (named.Count == 0)
        {
            return [KeepLatestMention(items)];
        }

        if (anonymousMentions > 0)
        {
            var latest = named.OrderByDescending(x => x.WhenUtc ?? DateTimeOffset.MinValue).First();
            latest.MentionCount = (latest.MentionCount ?? 1) + anonymousMentions;
        }

        return named;
    }

    private static NetworkVisit KeepLatestMention(IEnumerable<NetworkVisit> group)
    {
        var items = group.OrderByDescending(x => x.WhenUtc ?? DateTimeOffset.MinValue).ToList();
        var latest = items[0];
        latest.MentionCount = items.Sum(x => x.MentionCount ?? 1);
        return latest;
    }

    private static string Prefer(string current, string candidate) =>
        string.IsNullOrWhiteSpace(current) ? candidate : current;

    private static string JoinDetails(string current, string extra)
    {
        if (string.IsNullOrWhiteSpace(extra) || current.Contains(extra, StringComparison.OrdinalIgnoreCase))
        {
            return current;
        }

        return string.IsNullOrWhiteSpace(current) ? extra : $"{current} {extra}";
    }

    private static void AddDistinct(List<string> target, IEnumerable<string> values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value)
                && !target.Contains(value, StringComparer.OrdinalIgnoreCase))
            {
                target.Add(value);
            }
        }
    }
}
