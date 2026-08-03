using System.IO;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace UsbForensicAudit;

public static class ManualPdfGenerator
{
    private const string FontName = PdfFontHelper.DefaultFamily;

    public static void Generate(string outputPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
        PdfFontHelper.EnsureRegistered();

        Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.MarginHorizontal(36);
                page.MarginVertical(32);
                page.DefaultTextStyle(x => x.FontSize(10).FontFamily(FontName).LineHeight(1.35f));

                page.Header().Column(header =>
                {
                    header.Item().Text("UsbForensicAudit").SemiBold().FontSize(20).FontColor(Colors.Blue.Darken3);
                    header.Item().Text("Полная инструкция пользователя").FontSize(11).FontColor(Colors.Grey.Darken2);
                    header.Item().PaddingTop(6).LineHorizontal(1).LineColor(Colors.Grey.Lighten2);
                });

                page.Content().Column(column =>
                {
                    column.Spacing(10);
                    AddManualContent(column);
                });

                page.Footer().AlignCenter().Text(text =>
                {
                    text.DefaultTextStyle(x => x.FontSize(9).FontColor(Colors.Grey.Darken1));
                    text.Span("UsbForensicAudit v1.0 | ");
                    text.Span("Страница ");
                    text.CurrentPageNumber();
                    text.Span(" / ");
                    text.TotalPages();
                });
            });
        }).GeneratePdf(outputPath);
    }

    /// <summary>
    /// Текст руководства лежит в embedded-ресурсе ManualContent.txt с простой
    /// построчной разметкой: «# » — раздел, «## » — подзаголовок, «- » — пункт
    /// списка, «N. » — нумерованный пункт, «|a|b|» — строка таблицы (первая
    /// строка — шапка), «~ » — курсивная подпись, «=PAGEBREAK=» — разрыв
    /// страницы; прочие непустые строки — абзацы. Текст правится без
    /// изменения кода вёрстки и может быть отдан техническому писателю.
    /// </summary>
    private static void AddManualContent(ColumnDescriptor column)
    {
        List<string[]>? tableRows = null;

        void FlushTable()
        {
            if (tableRows is { Count: > 0 })
            {
                AddParsedTable(column, tableRows);
            }

            tableRows = null;
        }

        foreach (var rawLine in ReadContentLines())
        {
            var line = rawLine.TrimEnd();
            if (line.Length > 1 && line.StartsWith('|') && line.EndsWith('|'))
            {
                (tableRows ??= []).Add(line[1..^1].Split('|'));
                continue;
            }

            FlushTable();
            if (line.Length == 0)
            {
                continue;
            }

            if (line == "=PAGEBREAK=")
            {
                column.Item().PageBreak();
            }
            else if (line.StartsWith("# ", StringComparison.Ordinal))
            {
                SectionTitle(column, line[2..]);
            }
            else if (line.StartsWith("## ", StringComparison.Ordinal))
            {
                SubTitle(column, line[3..]);
            }
            else if (line.StartsWith("- ", StringComparison.Ordinal))
            {
                Bullet(column, line[2..]);
            }
            else if (line.StartsWith("~ ", StringComparison.Ordinal))
            {
                Signature(column, line[2..]);
            }
            else if (TryParseNumbered(line, out var number, out var text))
            {
                Numbered(column, number, text);
            }
            else
            {
                Paragraph(column, line);
            }
        }

        FlushTable();
    }

    private static IEnumerable<string> ReadContentLines()
    {
        using var stream = typeof(ManualPdfGenerator).Assembly
            .GetManifestResourceStream("UsbForensicAudit.ManualContent.txt")
            ?? throw new InvalidOperationException("Ресурс ManualContent.txt не найден в сборке.");
        using var reader = new StreamReader(stream);
        while (reader.ReadLine() is { } line)
        {
            yield return line;
        }
    }

    private static bool TryParseNumbered(string line, out int number, out string text)
    {
        var dot = line.IndexOf(". ", StringComparison.Ordinal);
        if (dot > 0 && int.TryParse(line[..dot], out number))
        {
            text = line[(dot + 2)..];
            return true;
        }

        number = 0;
        text = "";
        return false;
    }

    private static void AddParsedTable(ColumnDescriptor column, List<string[]> rows)
    {
        if (rows[0].Length == 3)
        {
            AddTable(column, rows.Select(r => (r[0], r[1], (string?)r[2])).ToArray());
        }
        else
        {
            AddTable(column, rows.Select(r => (r[0], r[1])).ToArray());
        }
    }

    private static void Signature(ColumnDescriptor column, string text)
    {
        column.Item().PaddingTop(8).Text(text).Italic().FontColor(Colors.Grey.Darken1);
    }

    private static void SectionTitle(ColumnDescriptor column, string title) =>
        PdfComponents.PlainTitle(column, title, 13, paddingTop: 4, fontColor: Colors.Blue.Darken3);

    private static void SubTitle(ColumnDescriptor column, string title) =>
        PdfComponents.PlainTitle(column, title, 11, paddingTop: 2);

    private static void Paragraph(ColumnDescriptor column, string text)
    {
        column.Item().Text(text);
    }

    private static void Bullet(ColumnDescriptor column, string text)
    {
        column.Item().Row(row =>
        {
            row.ConstantItem(12).Text("•");
            row.RelativeItem().Text(text);
        });
    }

    private static void Numbered(ColumnDescriptor column, int number, string text)
    {
        column.Item().Row(row =>
        {
            row.ConstantItem(18).Text($"{number}.");
            row.RelativeItem().Text(text);
        });
    }

    private static void AddTable(ColumnDescriptor column, params (string Col1, string Col2)[] rows)
    {
        AddTable(column, rows.Select(r => (r.Col1, r.Col2, (string?)null)).ToArray());
    }

    private static void AddTable(ColumnDescriptor column, params (string Col1, string Col2, string? Col3)[] rows)
    {
        if (rows.Length == 0)
        {
            return;
        }

        column.Item().Table(table =>
        {
            table.ColumnsDefinition(columns =>
            {
                columns.RelativeColumn(1.1f);
                if (rows[0].Col3 is not null)
                {
                    columns.RelativeColumn(0.8f);
                }

                columns.RelativeColumn(2f);
            });

            for (var i = 0; i < rows.Length; i++)
            {
                var row = rows[i];
                var isHeader = i == 0;
                TableCell(table, row.Col1, isHeader);
                if (row.Col3 is not null)
                {
                    TableCell(table, row.Col2, isHeader);
                    TableCell(table, row.Col3, isHeader);
                }
                else
                {
                    TableCell(table, row.Col2, isHeader);
                }
            }
        });
    }

    private static void TableCell(TableDescriptor table, string text, bool header)
    {
        table.Cell().Border(0.5f).BorderColor(Colors.Grey.Lighten2).Padding(4).Element(cell =>
        {
            if (header)
            {
                cell.Text(text).FontFamily(FontName).SemiBold().FontSize(9);
            }
            else
            {
                cell.Text(text).FontFamily(FontName).FontSize(9);
            }
        });
    }
}
