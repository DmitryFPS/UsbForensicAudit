using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace UsbForensicAudit;

/// <summary>
/// Общая механика заголовков QuestPDF-генераторов. До выделения каждый из
/// четырёх генераторов (полный отчёт, записка, executive-сводка, руководство)
/// держал собственную копию SectionTitle/SubTitle. Здесь дедуплицирована
/// механика (плашка, отступы, отбивка) — собственный стиль каждого документа
/// сохраняется через параметры, внешний вид PDF не меняется.
/// </summary>
internal static class PdfComponents
{
    /// <summary>Заголовок в серой плашке с рамкой — стиль полного отчёта и executive-сводки.</summary>
    public static void BoxedTitle(
        ColumnDescriptor column,
        string text,
        float fontSize,
        float paddingVertical,
        Color? fontColor = null)
    {
        var span = column.Item()
            .PaddingTop(4)
            .Background(Colors.Grey.Lighten3)
            .Border(0.5f)
            .BorderColor(Colors.Grey.Lighten1)
            .PaddingVertical(paddingVertical)
            .PaddingHorizontal(8)
            .Text(text)
            .SemiBold()
            .FontSize(fontSize);

        if (fontColor is not null)
        {
            span.FontColor(fontColor.Value);
        }
    }

    /// <summary>Простой заголовок с отступом сверху — стиль записки и руководства.</summary>
    public static void PlainTitle(
        ColumnDescriptor column,
        string text,
        float fontSize,
        float paddingTop,
        bool bold = false,
        Color? fontColor = null)
    {
        var span = column.Item().PaddingTop(paddingTop).Text(text);
        span = bold ? span.Bold() : span.SemiBold();
        span = span.FontSize(fontSize);

        if (fontColor is not null)
        {
            span.FontColor(fontColor.Value);
        }
    }

    /// <summary>Горизонтальная линия-отбивка под заголовком раздела.</summary>
    public static void TitleRule(ColumnDescriptor column) =>
        column.Item().LineHorizontal(0.5f).LineColor(Colors.Grey.Lighten1);
}
