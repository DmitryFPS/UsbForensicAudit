namespace UsbForensicAudit;

/// <summary>
/// Одно событие журнала о связи: соединились, разорвали, не смогли соединиться.
/// </summary>
public sealed record NetworkSessionEvent(
    DateTimeOffset WhenUtc,
    string Role,
    string Outcome,
    string Reason = "",
    string Account = "",
    string Source = "",
    string Provenance = "");

/// <summary>Что означает событие: начало связи, её конец или неудачную попытку.</summary>
public static class NetworkSessionRole
{
    public const string Start = "Start";
    public const string End = "End";
    public const string Failure = "Failure";
}

/// <summary>
/// Сводит события журнала в сеансы связи.
///
/// Windows пишет подключение и отключение отдельными событиями, и без их сведения
/// в пары история выглядит столбцом одинаковых строк, по которому невозможно
/// сказать, сколько времени машина была в сети. Отключение при этом теряется
/// штатно: при выключении питания записать его уже некому. Поэтому сеанс с одним
/// известным концом — обычное дело, и выдумывать второй конец нельзя.
/// </summary>
public static class NetworkSessionPairing
{
    public static List<NetworkSession> Pair(IEnumerable<NetworkSessionEvent> events)
    {
        var sessions = new List<NetworkSession>();
        NetworkSession? open = null;

        foreach (var item in events.OrderBy(x => x.WhenUtc))
        {
            if (item.Role == NetworkSessionRole.Failure)
            {
                var moment = Create(item);
                moment.IsMoment = true;
                sessions.Add(moment);
                continue;
            }

            if (item.Role == NetworkSessionRole.Start)
            {
                // Два подключения подряд без отключения между ними: предыдущий
                // сеанс так и остаётся с неизвестным концом.
                open = Create(item);
                sessions.Add(open);
                continue;
            }

            if (open is not null && open.EndedUtc is null && open.StartedUtc <= item.WhenUtc)
            {
                open.EndedUtc = item.WhenUtc;
                open.Reason = FirstNotEmpty(item.Reason, open.Reason);
                open = null;
                continue;
            }

            // Отключение без известного начала: начало вытеснено из журнала.
            sessions.Add(new NetworkSession
            {
                EndedUtc = item.WhenUtc,
                Outcome = item.Outcome,
                Reason = item.Reason,
                Account = item.Account,
                Source = item.Source,
                Provenance = item.Provenance
            });
            open = null;
        }

        return [.. sessions.OrderByDescending(x => x.StartedUtc ?? x.EndedUtc ?? DateTimeOffset.MinValue)];
    }

    private static NetworkSession Create(NetworkSessionEvent item) => new()
    {
        StartedUtc = item.WhenUtc,
        Outcome = item.Outcome,
        Reason = item.Reason,
        Account = item.Account,
        Source = item.Source,
        Provenance = item.Provenance
    };

    private static string FirstNotEmpty(params string[] values) =>
        values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "";
}
