namespace UsbForensicAudit;

/// <summary>
/// Единый счёт сетевых связей для вкладки и всех отчётов.
///
/// Заводится по той же причине, по которой заведён счёт устройств: одна и та же
/// сеть встречается в реестре, в журнале службы автонастройки и в списке
/// профилей, и складывать эти вхождения нельзя. В заголовке должно стоять число
/// связей, а не число найденных записей.
/// </summary>
public sealed class NetworkConnectionSummary
{
    private readonly Dictionary<string, int> _byKind = new(StringComparer.OrdinalIgnoreCase);

    public int Connections { get; private set; }

    /// <summary>Связи, по которым данные могли уйти с машины.</summary>
    public int OutsideReach { get; private set; }

    /// <summary>Обращения: папки на серверах, подключённые диски, страницы.</summary>
    public int Visits { get; private set; }

    /// <summary>Сеансы связи, сведённые в пары «подключение — отключение».</summary>
    public int Sessions { get; private set; }

    public int CountOf(string kind) => _byKind.TryGetValue(kind, out var count) ? count : 0;

    public static NetworkConnectionSummary Create(IEnumerable<NetworkConnectionRecord> connections)
    {
        var summary = new NetworkConnectionSummary();
        foreach (var connection in connections)
        {
            summary.Connections++;
            summary._byKind[connection.Kind] = summary.CountOf(connection.Kind) + 1;
            summary.Visits += connection.Visits.Count;
            summary.Sessions += connection.Sessions.Count;
            if (connection.IsOutsideReach)
            {
                summary.OutsideReach++;
            }
        }

        return summary;
    }

    /// <summary>
    /// Заголовок для вкладки и сводки отчёта. Сначала называется главное — сети и
    /// то, куда по ним ходили, — и только затем побочные подробности.
    /// </summary>
    public string Describe()
    {
        if (Connections == 0)
        {
            return "Сетевых подключений не найдено. Это не значит, что их не было: "
                   + "журналы Wi-Fi и SMB невелики и вытесняются, а список сетей чистится "
                   + "вместе с профилями.";
        }

        var parts = new List<string>();
        AddPart(parts, NetworkConnectionKind.WiFi, "сетей Wi-Fi");
        AddPart(parts, NetworkConnectionKind.Wired, "проводных сетей");
        AddPart(parts, NetworkConnectionKind.Vpn, "туннелей VPN");
        AddPart(parts, NetworkConnectionKind.MobileBroadband, "мобильных подключений");
        AddPart(parts, NetworkConnectionKind.NetworkShare, "серверов с сетевыми папками");
        AddPart(parts, NetworkConnectionKind.RemoteDesktop, "узлов удалённого рабочего стола");
        AddPart(parts, NetworkConnectionKind.Bluetooth, "устройств по Bluetooth");
        AddPart(parts, NetworkConnectionKind.WebSite, "сайтов в истории браузера");

        var text = $"Найдено связей: {Connections}";
        if (parts.Count > 0)
        {
            text += " — " + string.Join(", ", parts);
        }

        text += ".";

        if (OutsideReach > 0)
        {
            text += $" Из них связей, по которым данные могли уйти с машины: {OutsideReach} "
                    + "(сетевые папки, удалённый стол, туннели VPN, Bluetooth).";
        }

        if (Visits > 0)
        {
            text += $" Записанных обращений: {Visits}.";
        }

        return text;
    }

    private void AddPart(List<string> parts, string kind, string noun)
    {
        var count = CountOf(kind);
        if (count > 0)
        {
            parts.Add($"{noun}: {count}");
        }
    }
}
