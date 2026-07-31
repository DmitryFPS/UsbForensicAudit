namespace UsbForensicAudit;

/// <summary>
/// Цвет строки для каждой категории записи. Раньше цвета были перечислены
/// прямо в разметке окна: добавили категорию в сборщике — а про цвет и подпись
/// забыли, и часть строк оставалась неокрашенной, будто их не разобрали.
/// Здесь перечень один, он же проверяется тестами.
/// </summary>
public static class DeviceCategoryPalette
{
    /// <summary>
    /// Категория, назначаемая записи по умолчанию, пока сборщик не определил
    /// её точнее. Такие строки красятся отдельным цветом: читатель должен
    /// видеть, что запись не разобрана, а не принимать её за служебную.
    /// </summary>
    public const string Unclassified = "Unknown";

    private static readonly Dictionary<string, DeviceCategoryColors> Palette =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["RealUsb"] = new("#0D3328", "#DFF6EA"),
            ["RelatedStorage"] = new("#3B3213", "#F8EFD2"),
            ["UsbFlagsTrace"] = new("#302A57", "#EEEAFE"),
            ["SupportArtifact"] = new("#1B2C3F", "#B9CBDD"),
            ["HistoricalResidual"] = new("#3A2436", "#F2DCEC"),
            [Unclassified] = new("#3A2A1E", "#F5DCC8")
        };

    public static IReadOnlyCollection<string> KnownCategories => Palette.Keys;

    public static DeviceCategoryColors For(string? category) =>
        !string.IsNullOrWhiteSpace(category) && Palette.TryGetValue(category, out var colors)
            ? colors
            : Palette[Unclassified];

    public static bool IsKnown(string? category) =>
        !string.IsNullOrWhiteSpace(category) && Palette.ContainsKey(category);
}

/// <summary>
/// Цвета в том виде, в каком их понимает разметка окна.
/// </summary>
public sealed record DeviceCategoryColors(string Background, string Foreground);
