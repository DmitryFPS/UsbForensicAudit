namespace UsbForensicAudit;

/// <summary>
/// Цвет строки во вкладке «Сетевые подключения». Цветом отделено то, по чему
/// данные могли уйти с машины, от обычного подключения к своей сети: сетевая
/// папка и узел удалённого стола не должны выглядеть так же, как воткнутый
/// сетевой провод.
/// </summary>
public static class NetworkConnectionPalette
{
    private static readonly Dictionary<string, DeviceCategoryColors> Palette =
        new(StringComparer.OrdinalIgnoreCase)
        {
            [NetworkConnectionKind.NetworkShare] = new("#0E5138", "#EAFFF4"),
            [NetworkConnectionKind.RemoteDesktop] = new("#5A3210", "#FFE8CF"),
            [NetworkConnectionKind.WiFi] = new("#14415C", "#DFF3FF"),
            [NetworkConnectionKind.Vpn] = new("#2C2550", "#C8C0F0"),
            [NetworkConnectionKind.MobileBroadband] = new("#123F4A", "#CFF4FA"),
            [NetworkConnectionKind.Bluetooth] = new("#1B2E6B", "#D6DEFF"),
            [NetworkConnectionKind.Wired] = new("#1B2C3F", "#9FB4C8"),
            [NetworkConnectionKind.Nfc] = new("#3A2A1E", "#F5DCC8"),
            [NetworkConnectionKind.WebSite] = new("#33223A", "#DCC4E6"),
            [NetworkConnectionKind.Unknown] = new("#26262B", "#D6D6DC")
        };

    public static IReadOnlyCollection<string> KnownGroups => Palette.Keys;

    public static DeviceCategoryColors For(string? kind) =>
        !string.IsNullOrWhiteSpace(kind) && Palette.TryGetValue(kind, out var colors)
            ? colors
            : Palette[NetworkConnectionKind.Unknown];

    public static bool IsKnown(string? kind) =>
        !string.IsNullOrWhiteSpace(kind) && Palette.ContainsKey(kind);
}
