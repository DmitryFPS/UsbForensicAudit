using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace UsbForensicAudit;

internal static class ExecutiveBriefPdfReport
{
    private const string Title = "Сводный отчёт по проверке USB";
    private const float BodyFont = 9.5f;

    public static void Generate(string path, ForensicReportContext ctx)
    {
        var result = ctx.Result;

        Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4.Landscape());
                page.MarginHorizontal(28);
                page.MarginVertical(22);
                page.DefaultTextStyle(x => x
                    .FontSize(BodyFont)
                    .FontFamily(PdfFontHelper.DefaultFamily)
                    .LineHeight(1.25f));

                page.Header().Column(header =>
                {
                    header.Item().Row(row =>
                    {
                        row.RelativeItem().Text(T(Title)).SemiBold().FontSize(16).FontColor(Colors.Blue.Darken3);
                        row.ConstantItem(160).AlignRight().Text(text =>
                        {
                            text.DefaultTextStyle(x => x.FontSize(8).FontFamily(PdfFontHelper.DefaultFamily));
                            text.Span("Стр. ");
                            text.CurrentPageNumber();
                            text.Span(" / ");
                            text.TotalPages();
                        });
                    });
                    header.Item().PaddingTop(4).LineHorizontal(0.75f).LineColor(Colors.Grey.Lighten1);
                });

                page.Content().Column(column =>
                {
                    column.Spacing(8);
                    AppendOverviewPage(column, ctx);
                    AppendIncidentsPage(column, ctx);
                    AppendConclusionsPage(column, ctx);
                });

                page.Footer().AlignCenter().Text(T(
                        $"Сформировано: {DateDisplay.FormatMoscow(DateTimeOffset.UtcNow)}  |  Даты в отчёте — московское время (МСК)"))
                    .FontSize(7.5f)
                    .FontColor(Colors.Grey.Darken1);
            });
        }).GeneratePdf(path);
    }

    private static void AppendOverviewPage(ColumnDescriptor column, ForensicReportContext ctx)
    {
        var result = ctx.Result;
        var risk = GetRiskLevel(ctx);
        var userName = string.IsNullOrWhiteSpace(result.UserName) ? "не определено" : result.UserName;
        var adminRights = result.IsAdministrator ? "да" : "нет";

        SubTitle(column, "1. Общие сведения");
        AddTwoColumnTable(column,
        [
            ("Компьютер", result.ComputerName),
            ("Пользователь", userName),
            ("Windows", result.WindowsVersion),
            ("Установка Windows", result.OsInstalledAtText),
            ("Сканирование", DateDisplay.FormatMoscow(result.StartedAtUtc)),
            ("Длительность", ctx.ScanDurationText),
            ("Права администратора", adminRights),
            ("Общая оценка риска", risk.Label)
        ]);

        SubTitle(column, "2. Резюме");
        column.Item().Background(Colors.Grey.Lighten4).Border(0.5f).BorderColor(Colors.Grey.Lighten1).Padding(10)
            .Text(T(BuildExecutiveSummary(ctx, risk))).FontSize(BodyFont).LineHeight(1.3f);

        SubTitle(column, "3. Ключевые показатели");
        AddMetricsTable(column,
        [
            ("USB-устройств", result.Devices.Count.ToString()),
            ("Реальных USB", ctx.RealDevices.Count.ToString()),
            ("Доказательств", result.Evidence.Count.ToString()),
            ("Подозрительных", ctx.SuspiciousCount.ToString()),
            ("Высокий риск", ctx.HighRiskCount.ToString()),
            ("Предупреждений", result.SourceWarnings.Count.ToString())
        ]);
    }

    private static void AppendIncidentsPage(ColumnDescriptor column, ForensicReportContext ctx)
    {
        column.Item().PageBreak();
        SubTitle(column, "4. Подозрительные события (топ-8)");

        if (ctx.SuspiciousFindings.Count == 0)
        {
            column.Item().Text(T("Подозрительных признаков очистки или сокрытия следов не обнаружено."));
        }
        else
        {
            AddCompactTable(column,
            [
                ("Дата и время", 1.2f),
                ("Риск", 0.8f),
                ("Что найдено", 2f),
                ("Инициатор / инструмент", 1.5f)
            ],
            ctx.SuspiciousFindings.Take(8).Select(f => new[]
            {
                f.TimestampText,
                f.SeverityText,
                f.Finding,
                $"{f.InitiatorText}; {f.PossibleToolText}"
            }));
        }

        SubTitle(column, "5. Значимые USB-устройства (топ-10)");
        var notableDevices = ctx.RealDevices
            .OrderByDescending(d => d.LastSeenUtc ?? d.FirstConnectedUtc ?? DateTimeOffset.MinValue)
            .Take(10)
            .ToArray();

        if (notableDevices.Length == 0)
        {
            column.Item().Text(T("Реальные USB-устройства в истории не зафиксированы."));
        }
        else
        {
            AddCompactTable(column,
            [
                ("Устройство", 1.5f),
                ("Производитель", 1f),
                ("Серийный номер", 1f),
                ("Последняя активность", 1.1f),
                ("Подключали", 1.1f)
            ],
            notableDevices.Select(d => new[]
            {
                d.DisplayName,
                d.ManufacturerText,
                d.SerialText,
                d.LastSeenText,
                d.FirstConnectedText
            }));
        }

        SubTitle(column, "6. Последние значимые события (топ-12)");
        var highlights = ctx.Timeline
            .Where(e => !e.Source.Equals("Correlation", StringComparison.OrdinalIgnoreCase))
            .Take(12)
            .ToArray();

        if (highlights.Length == 0)
        {
            column.Item().Text(T("События не зафиксированы."));
        }
        else
        {
            AddCompactTable(column,
            [
                ("Дата и время", 1.1f),
                ("Событие", 1.1f),
                ("Источник", 1f),
                ("Описание", 2.8f)
            ],
            highlights.Select(e => new[]
            {
                e.TimestampText,
                e.EvidenceCategoryText,
                e.SourceText,
                T(e.Summary, 260)
            }));
        }
    }

    private static void AppendConclusionsPage(ColumnDescriptor column, ForensicReportContext ctx)
    {
        column.Item().PageBreak();
        var risk = GetRiskLevel(ctx);

        SubTitle(column, "7. Выводы");
        foreach (var paragraph in BuildConclusions(ctx, risk))
        {
            column.Item().PaddingBottom(3).Text(T(paragraph));
        }

        SubTitle(column, "8. Рекомендуемые действия");
        foreach (var action in BuildRecommendations(ctx, risk))
        {
            column.Item().PaddingBottom(2).Text(T($"- {action}"));
        }

        if (ctx.Result.SourceWarnings.Count > 0)
        {
            SubTitle(column, "9. Ограничения проверки");
            column.Item().Text(T(
                    $"При сборе данных зафиксировано {ctx.Result.SourceWarnings.Count} предупреждений. " +
                    "Часть источников могла быть недоступна — для полной картины используйте полный PDF-отчёт."))
                .FontSize(9)
                .FontColor(Colors.Grey.Darken2);

            foreach (var warning in ctx.Result.SourceWarnings.Take(5))
            {
                column.Item().Text(T($"- {warning}")).FontSize(9);
            }

            if (ctx.Result.SourceWarnings.Count > 5)
            {
                column.Item().Text(T($"... и ещё {ctx.Result.SourceWarnings.Count - 5} (см. полный отчёт)."))
                    .FontSize(9)
                    .FontColor(Colors.Grey.Darken1);
            }
        }

        column.Item().PaddingTop(6).Background(Colors.Blue.Lighten5).Border(0.5f).BorderColor(Colors.Blue.Lighten3)
            .Padding(8).Text(T(
                "Сводная версия отчёта (2–3 страницы). " +
                "Полный отчёт формируется кнопкой «Полный PDF»."))
            .FontSize(9);
    }

    private static RiskAssessment GetRiskLevel(ForensicReportContext ctx)
    {
        if (ctx.HighRiskCount > 0)
        {
            return new RiskAssessment("Высокий");
        }

        if (ctx.SuspiciousCount > 0)
        {
            return new RiskAssessment("Средний");
        }

        return new RiskAssessment("Низкий");
    }

    private static string BuildExecutiveSummary(ForensicReportContext ctx, RiskAssessment risk)
    {
        var result = ctx.Result;
        if (ctx.HighRiskCount > 0)
        {
            return
                $"На компьютере {result.ComputerName} выявлено {ctx.HighRiskCount} признак(ов) высокого риска " +
                $"и {ctx.SuspiciousCount} подозрительных записей, связанных с возможным сокрытием следов работы с USB. " +
                $"В истории зафиксировано {ctx.RealDevices.Count} реальных USB-устройств и {result.Evidence.Count} доказательств. " +
                "Рекомендуется детальная проверка и сохранение полного отчёта.";
        }

        if (ctx.SuspiciousCount > 0)
        {
            return
                $"На компьютере {result.ComputerName} обнаружено {ctx.SuspiciousCount} подозрительных записей, " +
                $"требующих внимания специалиста. Критических находок: {ctx.HighRiskCount}. " +
                $"Всего устройств: {result.Devices.Count}, реальных USB: {ctx.RealDevices.Count}. " +
                "Общая оценка риска: средний.";
        }

        return
            $"Проверка USB-устройств на компьютере {result.ComputerName} завершена без признаков сокрытия следов. " +
            $"Зафиксировано {ctx.RealDevices.Count} реальных USB-устройств, собрано {result.Evidence.Count} доказательств. " +
            "Общая оценка риска: низкий. Детальный отчёт рекомендуется сохранить для архива.";
    }

    private static IEnumerable<string> BuildConclusions(ForensicReportContext ctx, RiskAssessment risk)
    {
        yield return $"Общая оценка риска по результатам сканирования: {risk.Label.ToLowerInvariant()}.";

        if (ctx.HighRiskCount > 0)
        {
            yield return
                $"Имеются признаки, которые могут указывать на намеренное удаление или сокрытие следов подключения USB-устройств ({ctx.HighRiskCount} записей высокого риска).";
        }
        else if (ctx.SuspiciousCount > 0)
        {
            yield return
                $"Обнаружены косвенные признаки возможной очистки или изменения следов ({ctx.SuspiciousCount} подозрительных записей).";
        }
        else
        {
            yield return "Явных признаков очистки журналов или сокрытия USB-активности не выявлено.";
        }

        yield return
            $"В истории системы учтено {ctx.RealDevices.Count} реальных USB-устройств; " +
            $"собрано {ctx.Result.Evidence.Count} записей из реестра, журналов Windows и пользовательских артефактов.";

        if (!ctx.Result.IsAdministrator)
        {
            yield return "Сканирование выполнено без прав администратора — часть источников могла быть недоступна.";
        }

        if (ctx.ExternalUtilitySnapshot is not null
            && (ctx.ExternalUtilitySnapshot.Rows.Count > 0 || ctx.ExternalUtilitySnapshot.HistoricalLaunches.Count > 0))
        {
            yield return "В полный PDF включён раздел по сторонним USB-утилитам (считанное окно или ручной ввод, плюс исторические запуски).";
        }
    }

    private static IEnumerable<string> BuildRecommendations(ForensicReportContext ctx, RiskAssessment risk)
    {
        if (ctx.HighRiskCount > 0 || ctx.SuspiciousCount > 0)
        {
            yield return "Сохранить полный PDF-отчёт и передать его специалисту по информационной безопасности.";
            yield return "Сопоставить подозрительные записи с политикой использования съёмных носителей.";
            yield return "При необходимости провести повторное сканирование с правами администратора.";
        }
        else
        {
            yield return "Сохранить полный отчёт в архив как подтверждение проведённой проверки.";
            yield return "При подозрении на инцидент выполнить повторное сканирование до отключения питания ПК.";
        }

        yield return "Не удалять папку данных программы до завершения расследования.";
        yield return "При выявлении конкретного устройства запросить его у владельца для идентификации по серийному номеру.";
    }

    private static void SubTitle(ColumnDescriptor column, string title)
    {
        column.Item().PaddingTop(4).Background(Colors.Grey.Lighten3).Border(0.5f).BorderColor(Colors.Grey.Lighten1)
            .PaddingVertical(4).PaddingHorizontal(8)
            .Text(T(title)).SemiBold().FontSize(10.5f).FontColor(Colors.Blue.Darken3);
    }

    private static void AddMetricsTable(ColumnDescriptor column, IReadOnlyList<(string Label, string Value)> metrics)
    {
        column.Item().Table(table =>
        {
            table.ColumnsDefinition(columns =>
            {
                columns.RelativeColumn();
                columns.RelativeColumn();
                columns.RelativeColumn();
                columns.RelativeColumn();
                columns.RelativeColumn();
                columns.RelativeColumn();
            });

            foreach (var metric in metrics)
            {
                table.Cell().Element(MetricCell).Column(cell =>
                {
                    cell.Item().AlignCenter().Text(T(metric.Label)).FontSize(8).FontColor(Colors.Grey.Darken2);
                    cell.Item().AlignCenter().PaddingTop(2).Text(T(metric.Value)).SemiBold().FontSize(14);
                });
            }
        });
    }

    private static void AddTwoColumnTable(ColumnDescriptor column, IReadOnlyList<(string Key, string? Value)> rows)
    {
        column.Item().Table(table =>
        {
            table.ColumnsDefinition(columns =>
            {
                columns.RelativeColumn(1.1f);
                columns.RelativeColumn(1.9f);
                columns.RelativeColumn(1.1f);
                columns.RelativeColumn(1.9f);
            });

            for (var index = 0; index < rows.Count; index += 2)
            {
                WriteKeyCell(table, rows[index].Key);
                WriteValueCell(table, DisplayOrDash(rows[index].Value));

                if (index + 1 < rows.Count)
                {
                    WriteKeyCell(table, rows[index + 1].Key);
                    WriteValueCell(table, DisplayOrDash(rows[index + 1].Value));
                }
                else
                {
                    WriteKeyCell(table, "");
                    WriteValueCell(table, "");
                }
            }
        });
    }

    private static string DisplayOrDash(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "—" : value;

    private static void WriteKeyCell(TableDescriptor table, string key)
    {
        table.Cell().Element(KeyCell).Text(T(key)).SemiBold().FontSize(8.5f);
    }

    private static void WriteValueCell(TableDescriptor table, string? value)
    {
        table.Cell().Element(ValueCell).Text(T(value)).FontSize(8.5f);
    }

    private static void AddCompactTable(
        ColumnDescriptor column,
        IReadOnlyList<(string Header, float Weight)> columns,
        IEnumerable<string[]> rows)
    {
        var materializedRows = rows.ToArray();
        if (materializedRows.Length == 0)
        {
            return;
        }

        column.Item().PaddingTop(2).Table(table =>
        {
            table.ColumnsDefinition(definition =>
            {
                foreach (var columnDef in columns)
                {
                    definition.RelativeColumn(columnDef.Weight);
                }
            });

            table.Header(header =>
            {
                foreach (var columnDef in columns)
                {
                    header.Cell().Element(HeaderCell).Text(T(columnDef.Header)).SemiBold().FontSize(8.5f);
                }
            });

            for (var rowIndex = 0; rowIndex < materializedRows.Length; rowIndex++)
            {
                var row = materializedRows[rowIndex];
                var zebra = rowIndex % 2 == 0 ? Colors.White : Colors.Grey.Lighten5;

                for (var index = 0; index < columns.Count; index++)
                {
                    var value = index < row.Length ? row[index] : "";
                    table.Cell().Element(cell => BodyCell(cell, zebra)).Text(T(value, 500)).FontSize(8.5f);
                }
            }
        });
    }

    private static IContainer KeyCell(IContainer container) =>
        container.Background(Colors.Grey.Lighten4).Border(0.5f).BorderColor(Colors.Grey.Lighten2).Padding(4);

    private static IContainer ValueCell(IContainer container) =>
        container.Border(0.5f).BorderColor(Colors.Grey.Lighten2).Padding(4);

    private static IContainer MetricCell(IContainer container) =>
        container.Border(0.5f).BorderColor(Colors.Grey.Lighten1).Background(Colors.White).Padding(6);

    private static IContainer HeaderCell(IContainer container) =>
        container.Background(Colors.Grey.Lighten3).Border(0.5f).BorderColor(Colors.Grey.Lighten1).Padding(3);

    private static IContainer BodyCell(IContainer container, string background) =>
        container.Background(background).Border(0.5f).BorderColor(Colors.Grey.Lighten2).Padding(3);

    private static string T(string? value, int maxLength = 4000) => ReportText.ForPdf(value, maxLength);

    private sealed record RiskAssessment(string Label);
}
