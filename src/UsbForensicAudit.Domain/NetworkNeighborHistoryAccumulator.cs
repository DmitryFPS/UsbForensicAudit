namespace UsbForensicAudit;

/// <summary>
/// Складывает наблюдения из очередного снимка обстановки в историю активности
/// устройств за сессию аудита.
///
/// Правила склейки простые и честные. Заводской MAC — единственный признак,
/// по которому устройство можно узнать между снимками, и наблюдения с одним
/// заводским MAC склеиваются в одну запись. Случайный (назначенный на месте)
/// MAC узнать между снимками нельзя: телефон в другой раз придёт под другим
/// адресом, — поэтому каждое такое наблюдение остаётся отдельной записью и
/// прямо помечается как ненадёжное. Устройство без MAC склеивается по IP, и
/// это тоже помечается: IP в сети может достаться другому устройству.
/// </summary>
public static class NetworkNeighborHistoryAccumulator
{
    /// <summary>
    /// Возвращает новую историю: прежние записи плюс наблюдения из нового
    /// снимка. Ни существующая история, ни записи снимка не изменяются.
    /// </summary>
    public static List<NetworkNeighborHistory> Merge(
        IEnumerable<NetworkNeighborHistory> existing,
        IEnumerable<NetworkNeighborRecord> newNeighbors,
        DateTimeOffset takenAtUtc)
    {
        var result = existing.Select(Clone).ToList();
        var byKey = result
            .Where(x => x.Key.Length > 0)
            .GroupBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

        foreach (var neighbor in newNeighbors)
        {
            var mac = MacAddress.Normalize(neighbor.MacAddress);
            var randomized = mac.Length > 0 && MacAddress.IsLocallyAssigned(mac);
            var key = BuildKey(mac, randomized, neighbor.IpAddress, takenAtUtc);

            if (key.Length > 0 && byKey.TryGetValue(key, out var known))
            {
                Append(known, neighbor, takenAtUtc);
                continue;
            }

            var created = Create(key, mac, randomized, neighbor, takenAtUtc);
            result.Add(created);
            if (key.Length > 0)
            {
                byKey[key] = created;
            }
        }

        return result
            .OrderByDescending(x => x.LastSeenUtc)
            .ThenByDescending(x => x.TimesSeen)
            .ThenBy(x => NeighborRole.Rank(x.Role))
            .ToList();
    }

    /// <summary>
    /// Ключ склейки. Заводской MAC узнаваем между снимками; случайный MAC
    /// получает неповторяемый ключ и потому никогда ни с чем не склеится;
    /// устройство без MAC опознаётся по IP — это лучше, чем ничего, но
    /// помечается отдельно.
    /// </summary>
    private static string BuildKey(string normalizedMac, bool randomized, string ipAddress, DateTimeOffset takenAtUtc)
    {
        if (normalizedMac.Length > 0)
        {
            return randomized
                ? $"random:{normalizedMac}:{takenAtUtc.UtcTicks}:{ipAddress}"
                : $"mac:{normalizedMac}";
        }

        var ip = ipAddress.Trim();
        return ip.Length > 0 ? $"ip:{ip}" : "";
    }

    private static NetworkNeighborHistory Create(
        string key,
        string normalizedMac,
        bool randomized,
        NetworkNeighborRecord neighbor,
        DateTimeOffset takenAtUtc)
    {
        var history = new NetworkNeighborHistory
        {
            Key = key,
            MacAddress = normalizedMac,
            IsRandomizedMac = randomized,
            IdentifiedByIpOnly = normalizedMac.Length == 0 && neighbor.IpAddress.Trim().Length > 0,
            Role = neighbor.Role,
            FirstSeenUtc = takenAtUtc,
            LastSeenUtc = takenAtUtc,
            TimesSeen = 1
        };

        AddDetails(history, neighbor, takenAtUtc);
        return history;
    }

    private static void Append(NetworkNeighborHistory history, NetworkNeighborRecord neighbor, DateTimeOffset takenAtUtc)
    {
        if (takenAtUtc < history.FirstSeenUtc)
        {
            history.FirstSeenUtc = takenAtUtc;
        }

        if (takenAtUtc > history.LastSeenUtc)
        {
            history.LastSeenUtc = takenAtUtc;
        }

        history.TimesSeen++;

        // Роль повышается, если устройство оказалось важнее, чем считалось:
        // сосед, оказавшийся шлюзом, в истории должен значиться шлюзом.
        if (NeighborRole.Rank(neighbor.Role) < NeighborRole.Rank(history.Role))
        {
            history.Role = neighbor.Role;
        }

        AddDetails(history, neighbor, takenAtUtc);
    }

    private static void AddDetails(NetworkNeighborHistory history, NetworkNeighborRecord neighbor, DateTimeOffset takenAtUtc)
    {
        AddUnique(history.IpAddresses, neighbor.IpAddress);
        AddUnique(history.Networks, neighbor.Network);
        AddUnique(history.Names, neighbor.HostName);
        AddUnique(history.Names, neighbor.NetbiosName);
        AddUnique(history.Names, neighbor.EnrichedName);

        history.Observations.Add(new NetworkNeighborObservation
        {
            TakenAtUtc = takenAtUtc,
            IpAddress = neighbor.IpAddress,
            Discovery = neighbor.Discovery,
            State = neighbor.State,
            Network = neighbor.Network,
            Name = neighbor.HostName.Length > 0
                ? neighbor.HostName
                : neighbor.NetbiosName.Length > 0
                    ? neighbor.NetbiosName
                    : neighbor.EnrichedName
        });
    }

    private static void AddUnique(List<string> values, string value)
    {
        var text = value.Trim();
        if (text.Length > 0 && !values.Any(x => x.Equals(text, StringComparison.OrdinalIgnoreCase)))
        {
            values.Add(text);
        }
    }

    private static NetworkNeighborHistory Clone(NetworkNeighborHistory source) => new()
    {
        Key = source.Key,
        MacAddress = source.MacAddress,
        IsRandomizedMac = source.IsRandomizedMac,
        IdentifiedByIpOnly = source.IdentifiedByIpOnly,
        Role = source.Role,
        FirstSeenUtc = source.FirstSeenUtc,
        LastSeenUtc = source.LastSeenUtc,
        TimesSeen = source.TimesSeen,
        IpAddresses = [.. source.IpAddresses],
        Networks = [.. source.Networks],
        Names = [.. source.Names],
        Observations = [.. source.Observations]
    };
}
