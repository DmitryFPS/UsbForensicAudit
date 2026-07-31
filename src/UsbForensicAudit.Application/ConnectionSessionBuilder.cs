namespace UsbForensicAudit;

/// <summary>
/// Собирает сеансы работы устройства из событий подключения и отключения.
/// </summary>
public static class ConnectionSessionBuilder
{
    /// <summary>
    /// Два события подключения подряд без отключения между ними обычно означают
    /// не два сеанса, а переинициализацию одного и того же: Windows перечисляет
    /// устройство несколько раз. Более близкие по времени пары объединяются.
    /// </summary>
    private static readonly TimeSpan ReenumerationWindow = TimeSpan.FromMinutes(2);

    public static IReadOnlyList<ConnectionSession> Build(
        IEnumerable<(DateTimeOffset TimestampUtc, bool IsConnect, string Provenance)> events)
    {
        var ordered = events
            .OrderBy(x => x.TimestampUtc)
            .ThenBy(x => x.IsConnect ? 0 : 1)
            .ToArray();

        var sessions = new List<ConnectionSession>();
        ConnectionSession? open = null;

        foreach (var item in ordered)
        {
            if (item.IsConnect)
            {
                if (open is not null)
                {
                    if (item.TimestampUtc - open.StartUtc <= ReenumerationWindow)
                    {
                        continue;
                    }

                    sessions.Add(open);
                }

                open = new ConnectionSession
                {
                    StartUtc = item.TimestampUtc,
                    StartProvenance = item.Provenance
                };
                continue;
            }

            if (open is null)
            {
                // Отключение без парного подключения: журнал начинается позже, чем
                // устройство подключили. Такой сеанс нельзя датировать началом.
                continue;
            }

            open.EndUtc = item.TimestampUtc;
            open.EndProvenance = item.Provenance;
            sessions.Add(open);
            open = null;
        }

        if (open is not null)
        {
            sessions.Add(open);
        }

        return sessions;
    }
}
