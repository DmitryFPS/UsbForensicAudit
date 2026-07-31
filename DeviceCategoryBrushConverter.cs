using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace UsbForensicAudit;

/// <summary>
/// Красит строку таблицы по категории записи. Цвета берутся из общей палитры,
/// а не перечисляются в разметке: иначе новая категория появляется в сборщике,
/// а строка остаётся неокрашенной.
/// </summary>
public sealed class DeviceCategoryBrushConverter : IValueConverter
{
    private static readonly Dictionary<string, SolidColorBrush> Cache = [];

    /// <summary>
    /// «Background» — цвет строки, «Foreground» — цвет текста.
    /// </summary>
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var colors = DeviceCategoryPalette.For(value as string);
        var hex = parameter as string == "Foreground" ? colors.Foreground : colors.Background;
        return Brush(hex);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();

    private static SolidColorBrush Brush(string hex)
    {
        if (Cache.TryGetValue(hex, out var cached))
        {
            return cached;
        }

        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        Cache[hex] = brush;
        return brush;
    }
}
