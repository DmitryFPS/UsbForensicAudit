using System.IO;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace UsbForensicAudit;

/// <summary>
/// Одностраничный отчёт для руководителя: без технических терминов, кодов и
/// таблиц с цифрами. Одна страница отвечает на три вопроса расследования,
/// даёт общую оценку и рекомендуемые действия. Всё техническое остаётся в
/// полном отчёте — здесь только выводы человеческим языком.
/// </summary>
internal static class ManagerOnePagePdfReport
{
    private const string Title = "Проверка использования USB-носителей — отчёт для руководителя";
    private const float BodyFont = 10.5f;

    public static void Generate(string path, ForensicReportContext ctx)
    {
        using var output = File.Create(path);
        Generate(output, ctx);
    }

    /// <summary>Пишет отчёт в поток: тесты проверяют содержимое без записи на диск.</summary>
    public static void Generate(Stream output, ForensicReportContext ctx)
    {
        var result = ctx.Result;
        var (riskLabel, riskColor) = OverallRisk(ctx);

        Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.MarginHorizontal(36);
                page.MarginVertical(30);
                page.DefaultTextStyle(x => x
                    .FontSize(BodyFont)
                    .FontFamily(PdfFontHelper.DefaultFamily)
                    .LineHeight(1.35f));

                page.Header().Column(header =>
                {
                    header.Item().Text(T(Title)).SemiBold().FontSize(15).FontColor(Colors.Blue.Darken3);
                    header.Item().PaddingTop(2).Text(T(HeaderLine(ctx))).FontSize(9).FontColor(Colors.Grey.Darken2);
                    header.Item().PaddingTop(6).LineHorizontal(0.75f).LineColor(Colors.Grey.Lighten1);
                });

                page.Content().PaddingTop(10).Column(column =>
                {
                    column.Spacing(10);

                    // Общая оценка — первое и самое крупное на странице.
                    column.Item()
                        .Background(Colors.Grey.Lighten4)
                        .Border(1).BorderColor(riskColor)
                        .Padding(12)
                        .Text(T($"Общая оценка: {riskLabel}"))
                        .FontSize(15).Bold().FontColor(riskColor);

                    AnswerBlock(column, "Подключали ли к компьютеру внешние носители?", DevicesAnswer(ctx), DevicesColor(ctx));
                    AnswerBlock(column, "Работали ли с файлами на носителях?", FileActivityAnswer(ctx), FileActivityColor(ctx));
                    AnswerBlock(column, "Пытались ли скрыть следы?", CleanupAnswer(ctx), CleanupColor(ctx));

                    column.Item().PaddingTop(2).Text(T("Рекомендуемые действия")).SemiBold().FontSize(12);
                    foreach (var action in RecommendedActions(ctx))
                    {
                        column.Item().PaddingLeft(8).Text(T("•  " + action));
                    }
                });

                page.Footer().Column(footer =>
                {
                    footer.Item().LineHorizontal(0.5f).LineColor(Colors.Grey.Lighten1);
                    footer.Item().PaddingTop(4).Text(T(
                            "Этот отчёт — краткие выводы без технических данных. Полные доказательства, устройства, "
                            + "хронология и методика — в полном отчёте той же программы."))
                        .FontSize(8).FontColor(Colors.Grey.Darken1);
                    footer.Item().PaddingTop(2).Text(T(
                            $"Сформировано: {DateDisplay.FormatMoscow(DateTimeOffset.UtcNow)} ({DateDisplay.ZoneLabel})  |  UsbForensicAudit"))
                        .FontSize(8).FontColor(Colors.Grey.Darken1);
                });
            });
        }).GeneratePdf(output);
    }

    private static string HeaderLine(ForensicReportContext ctx)
    {
        var result = ctx.Result;
        var parts = new List<string>();
        foreach (var (label, value) in ctx.Case.DisplayFields())
        {
            parts.Add($"{label}: {value}");
        }

        parts.Add($"Компьютер: {result.ComputerName}");
        parts.Add($"Проверка выполнена: {DateDisplay.FormatMoscow(result.StartedAtUtc)}");
        return string.Join("  |  ", parts);
    }

    private static void AnswerBlock(ColumnDescriptor column, string question, string answer, string color)
    {
        column.Item().Column(block =>
        {
            block.Item().Text(T(question)).SemiBold().FontSize(12);
            block.Item().PaddingTop(2).PaddingLeft(8).Text(T(answer)).FontColor(color);
        });
    }

    private static (string Label, string Color) OverallRisk(ForensicReportContext ctx)
    {
        if (ctx.HighRiskCount > 0 || ctx.Exfiltration.ConfirmedCount > 0 || ctx.PolicySummary.HasViolations)
        {
            return ("требуется разбирательство", Colors.Red.Darken2);
        }

        if (ctx.SuspiciousCount > 0 || ctx.Exfiltration.HasAnyIndication || ctx.AttentionCount > 0)
        {
            return ("требуется проверка", Colors.Orange.Darken3);
        }

        return ("существенных рисков не выявлено", Colors.Green.Darken2);
    }

    private static string DevicesColor(ForensicReportContext ctx) =>
        ctx.PolicySummary.HasViolations ? Colors.Red.Darken2 : Colors.Grey.Darken3;

    private static string DevicesAnswer(ForensicReportContext ctx)
    {
        var external = ctx.ListedDevices.Where(x => x.IsExternalDevice).ToArray();
        if (external.Length == 0)
        {
            return "Следов подключения флешек, внешних дисков или телефонов не найдено. "
                   + "Отсутствие следов не гарантирует, что подключений не было вовсе.";
        }

        var names = external
            .Select(x => x.DisplayName)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(3)
            .ToArray();
        var lastSeen = external
            .Select(x => x.LastSeenUtc)
            .Where(x => x is not null)
            .OrderByDescending(x => x)
            .FirstOrDefault();

        var text = $"Да. Зафиксировано внешних устройств: {external.Length}";
        if (names.Length > 0)
        {
            text += $" (в том числе: {string.Join("; ", names)})";
        }

        text += lastSeen is not null
            ? $". Последний раз внешнее устройство было активно {DateDisplay.FormatMoscow(lastSeen.Value)}."
            : ".";

        if (ctx.PolicySummary.HasViolations)
        {
            text += $" Важно: {ctx.PolicySummary.Violations.Count} подключение(й) нарушает список разрешённых устройств.";
        }

        return text;
    }

    // Прежний вопрос «Уходили ли данные?» с зелёным «не найдено» был нечестен:
    // Windows фиксирует копирование на флешку лишь при редком стечении условий,
    // и молчание артефактов ничего не доказывает. Вопрос заменён на тот, на
    // который следы отвечают надёжно, — работали ли с файлами на носителях;
    // признаки выноса, когда они есть, по-прежнему поднимают цвет и текст.
    private static string FileActivityColor(ForensicReportContext ctx) =>
        ctx.Exfiltration.ConfirmedCount > 0 ? Colors.Red.Darken2
        : ctx.Exfiltration.HasAnyIndication ? Colors.Orange.Darken3
        : Colors.Grey.Darken3;

    private static string FileActivityAnswer(ForensicReportContext ctx)
    {
        var exf = ctx.Exfiltration;
        var withActivity = ctx.DevicesWithActivity().ToArray();
        var actions = withActivity.Sum(x => x.History.Entries.Count);
        var lastAction = withActivity
            .SelectMany(x => x.History.Entries)
            .Select(x => x.TimestampUtc)
            .OrderByDescending(x => x)
            .Cast<DateTimeOffset?>()
            .FirstOrDefault();

        var text = withActivity.Length > 0
            ? $"Да. Зафиксировано {actions} действие(й) с файлами и папками на {withActivity.Length} носителе(ях): "
              + "открытия документов, просмотр папок, запуск программ."
              + (lastAction is not null ? $" Последнее действие: {DateDisplay.FormatMoscow(lastAction.Value)}." : "")
            : "Следов открытия файлов, просмотра папок или запуска программ с носителей не найдено.";

        if (exf.ConfirmedCount > 0)
        {
            text += $" Важно: подтверждено копирование {exf.ConfirmedCount} файла(ов) на носитель — список в полном отчёте.";
        }
        else if (exf.HasAnyIndication)
        {
            text += $" Есть признаки возможного копирования ({exf.OutboundCount + exf.UndirectedCount}) — требуется ручная проверка.";
        }
        else
        {
            text += " Следов копирования на носители нет, но Windows фиксирует копирование лишь частично — "
                    + "их отсутствие не доказывает, что данные не уходили.";
        }

        return text;
    }

    private static string CleanupColor(ForensicReportContext ctx) =>
        ctx.HighRiskCount > 0 ? Colors.Red.Darken2
        : ctx.SuspiciousCount > 0 || ctx.AttentionCount > 0 ? Colors.Orange.Darken3
        : Colors.Green.Darken2;

    private static string CleanupAnswer(ForensicReportContext ctx)
    {
        if (ctx.HighRiskCount > 0)
        {
            return $"Вероятно, да. Найдено {ctx.HighRiskCount} серьёзных признака(ов) удаления следов работы с USB "
                   + $"(всего подозрительных записей: {ctx.SuspiciousCount}). Это само по себе повод для разбирательства.";
        }

        if (ctx.SuspiciousCount > 0)
        {
            return $"Возможно. Найдено {ctx.SuspiciousCount} подозрительных признака(ов) — нужна проверка обстоятельств.";
        }

        if (ctx.AttentionCount > 0)
        {
            return $"Явной очистки не найдено, но есть {ctx.AttentionCount} обстоятельство(а), требующее внимания: "
                   + "например, на компьютере запускали или хранили программы, умеющие удалять следы.";
        }

        return "Признаков удаления или сокрытия следов не найдено.";
    }

    private static IReadOnlyList<string> RecommendedActions(ForensicReportContext ctx)
    {
        var actions = new List<string>();

        if (ctx.Exfiltration.ConfirmedCount > 0)
        {
            actions.Add("Установить владельца носителя, на который копировали файлы, и ценность скопированной информации.");
        }

        if (ctx.HighRiskCount > 0)
        {
            actions.Add("Выяснить, кто и с какой целью удалял следы работы с USB — время событий указано в полном отчёте.");
        }

        if (ctx.PolicySummary.HasViolations)
        {
            actions.Add("Разобраться, почему подключались устройства не из списка разрешённых, и при необходимости изъять их.");
        }

        if (actions.Count == 0 && (ctx.SuspiciousCount > 0 || ctx.Exfiltration.HasAnyIndication || ctx.AttentionCount > 0))
        {
            actions.Add("Поручить специалисту проверить отмеченные в полном отчёте спорные события.");
        }

        if (actions.Count == 0)
        {
            actions.Add("Экстренных мер не требуется. Рекомендуется повторять проверку регулярно или включить фоновый мониторинг.");
        }
        else
        {
            actions.Add("Сохранить пакет доказательств (кнопка в программе) — он пригодится при официальном разбирательстве.");
        }

        return actions;
    }

    private static string T(string? value, int maxLength = 4000) => ReportText.ForPdf(value, maxLength);
}
