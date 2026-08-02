using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace UsbForensicAudit;

/// <summary>
/// Красит строку таблицы сетевых связей по виду связи. Цвета берутся из общей
/// палитры, а не перечисляются в разметке: иначе новый вид связи появляется в
/// коде, а строка остаётся неокрашенной.
/// </summary>
public sealed class NetworkConnectionBrushConverter : IValueConverter
{
    private static readonly Dictionary<string, SolidColorBrush> Cache = [];

    /// <summary>«Background» — цвет строки, «Foreground» — цвет текста.</summary>
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var colors = NetworkConnectionPalette.For(value as string);
        return Brush(parameter as string == "Foreground" ? colors.Foreground : colors.Background);
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
