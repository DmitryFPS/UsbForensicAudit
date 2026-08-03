using ClosedXML.Excel;

namespace UsbForensicAudit;

/// <summary>
/// Общее оформление Excel-отчётов: фирменные цвета, тонкие рамки и расчёт
/// высоты строк. До выделения ExcelReportGenerator и AnalystNoteExcelReport
/// держали дословные копии этих членов, и копии уже начали расходиться.
/// Подключается через using static — вызовы в генераторах не меняются.
/// </summary>
internal static class ExcelStyleHelper
{
    public static readonly XLColor HeaderColor = XLColor.FromHtml("#1F4E78");
    public static readonly XLColor SectionColor = XLColor.FromHtml("#D9EAF7");
    public static readonly XLColor BorderColor = XLColor.FromHtml("#AFC4D4");

    public const double MinimumDataRowHeight = 21;
    public const double MaximumDataRowHeight = 108;

    public static void ApplyThinBorder(IXLRange range)
    {
        range.Style.Border.TopBorder = XLBorderStyleValues.Thin;
        range.Style.Border.BottomBorder = XLBorderStyleValues.Thin;
        range.Style.Border.LeftBorder = XLBorderStyleValues.Thin;
        range.Style.Border.RightBorder = XLBorderStyleValues.Thin;
        range.Style.Border.TopBorderColor = BorderColor;
        range.Style.Border.BottomBorderColor = BorderColor;
        range.Style.Border.LeftBorderColor = BorderColor;
        range.Style.Border.RightBorderColor = BorderColor;
    }

    /// <summary>
    /// Оценивает высоту строки по самой «многострочной» ячейке: перенос по
    /// ширине колонки плюс явные переводы строк в значении.
    /// </summary>
    public static double EstimateRowHeight(
        IEnumerable<(string Value, double Width)> values,
        double minimum,
        double maximum)
    {
        var lineCount = 1;
        foreach (var (value, width) in values)
        {
            var usableWidth = Math.Max(8, width - 2);
            var cellLines = value
                .Replace("\r\n", "\n", StringComparison.Ordinal)
                .Split('\n')
                .Sum(line => Math.Max(1, (int)Math.Ceiling(line.Length / usableWidth)));
            lineCount = Math.Max(lineCount, cellLines);
        }

        return Math.Clamp(9 + lineCount * 12, minimum, maximum);
    }
}
