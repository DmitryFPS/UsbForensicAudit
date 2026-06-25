using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace UsbForensicAudit;

internal static class ForensicPdfReport
{
    private const float BodyFont = 8.5f;
    private const float HeaderFont = 9f;
    private const float SectionFont = 12f;

    public static void Generate(string path, ForensicReportContext ctx)
    {
        var result = ctx.Result;
        var externalSnapshot = ctx.ExternalUtilitySnapshot;

        Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4.Landscape());
                page.MarginHorizontal(22);
                page.MarginVertical(18);
                page.DefaultTextStyle(x => x
                    .FontSize(BodyFont)
                    .FontFamily(PdfFontHelper.DefaultFamily)
                    .LineHeight(1.2f));

                page.Header().Column(header =>
                {
                    header.Item().Row(row =>
                    {
                        row.RelativeItem().Column(left =>
                        {
                            left.Item().Text(T(ForensicReportBuilder.ReportTitle)).SemiBold().FontSize(14);
                            left.Item().Text(T(
                                    $"Компьютер: {result.ComputerName}  |  Пользователь: {result.UserName}  |  " +
                                    $"Сканирование: {DateDisplay.FormatMoscow(result.StartedAtUtc)}"))
                                .FontSize(8)
                                .FontColor(Colors.Grey.Darken2);
                        });

                        row.ConstantItem(170).AlignRight().Column(right =>
                        {
                            right.Item().AlignRight().Text(T("Аудит USB / форензика")).FontSize(8).FontColor(Colors.Grey.Darken1);
                            right.Item().AlignRight().Text(text =>
                            {
                                text.DefaultTextStyle(x => x.FontSize(8).FontFamily(PdfFontHelper.DefaultFamily));
                                text.Span("Страница ");
                                text.CurrentPageNumber();
                                text.Span(" / ");
                                text.TotalPages();
                            });
                        });
                    });

                    header.Item().PaddingTop(4).LineHorizontal(0.75f).LineColor(Colors.Grey.Lighten1);
                });

                page.Content().Column(column =>
                {
                    column.Spacing(6);
                    AppendCoverSection(column, ctx);
                    AppendSummarySection(column, ctx, pageBreakBefore: true);
                    AppendIncidentSection(column, ctx, pageBreakBefore: true);
                    AppendCleanupSection(column, ctx, pageBreakBefore: true);
                    AppendDevicesSection(column, ctx, pageBreakBefore: true);
                    AppendDossiersSection(column, ctx, pageBreakBefore: true);
                    AppendEvidenceSection(column, ctx, pageBreakBefore: true);
                    AppendWarningsSection(column, ctx, pageBreakBefore: true);
                    AppendMethodologySection(column, pageBreakBefore: true);
                    if (externalSnapshot is not null)
                    {
                        AppendExternalUtilitiesSection(column, externalSnapshot, pageBreakBefore: true);
                    }
                });

                page.Footer().AlignCenter().Text(T(
                        $"Сформировано: {DateDisplay.FormatMoscow(DateTimeOffset.UtcNow)}  |  Все даты в отчёте — московское время (МСК)"))
                    .FontSize(7)
                    .FontColor(Colors.Grey.Darken1);
            });
        }).GeneratePdf(path);
    }

    private static void AppendCoverSection(ColumnDescriptor column, ForensicReportContext ctx)
    {
        var result = ctx.Result;
        SectionTitle(column, "Метаданные сканирования");

        AddKeyValueGrid(column,
        [
            ("Компьютер", result.ComputerName),
            ("Пользователь", result.UserName),
            ("Windows", result.WindowsVersion),
            ("Установка Windows", result.OsInstalledAtText),
            ("Начало сканирования", DateDisplay.FormatMoscow(result.StartedAtUtc)),
            ("Окончание сканирования", DateDisplay.FormatMoscow(result.FinishedAtUtc)),
            ("Длительность", ctx.ScanDurationText),
            ("Права администратора", result.IsAdministrator ? "да" : "нет")
        ]);

        column.Item().PaddingTop(2).Text(T(result.OsInstallGraceNote)).FontSize(7.5f).FontColor(Colors.Grey.Darken2);
    }

    private static void AppendSummarySection(ColumnDescriptor column, ForensicReportContext ctx, bool pageBreakBefore)
    {
        if (pageBreakBefore)
        {
            column.Item().PageBreak();
        }

        SectionTitle(column, "1. Сводка для расследования");

        column.Item().Row(row =>
        {
            row.Spacing(8);
            StatBox(row, "Устройств", ctx.Result.Devices.Count.ToString());
            StatBox(row, "Реальных USB", ctx.RealDevices.Count.ToString());
            StatBox(row, "Доказательств", ctx.Result.Evidence.Count.ToString());
            StatBox(row, "Признаков очистки", ctx.Result.CleanupFindings.Count.ToString());
            StatBox(row, "Подозрительных", ctx.SuspiciousCount.ToString());
            StatBox(row, "Высокий риск", ctx.HighRiskCount.ToString());
            StatBox(row, "Предупреждений", ctx.Result.SourceWarnings.Count.ToString());
        });

        SubTitle(column, "Устройства по типам");
        AddDataTable(column,
            [("Тип", 4f), ("Количество", 1f)],
            ctx.DevicesByCategory.Select(x => new[] { x.Category, x.Count.ToString() }));

        SubTitle(column, "Доказательства по источникам");
        AddDataTable(column,
            [("Источник", 4f), ("Записей", 1f)],
            ctx.EvidenceBySource.Select(x => new[] { x.Source, x.Count.ToString() }));
    }

    private static void AppendIncidentSection(ColumnDescriptor column, ForensicReportContext ctx, bool pageBreakBefore)
    {
        if (pageBreakBefore)
        {
            column.Item().PageBreak();
        }

        SectionTitle(column, "2. Возможные инциденты");
        if (ctx.SuspiciousFindings.Count == 0)
        {
            column.Item().Text(T("Подозрительных признаков очистки или сокрытия следов не обнаружено."));
            return;
        }

        AddDataTable(column,
        [
            ("Дата и время", 1.2f),
            ("Тип действия", 0.9f),
            ("Риск / статус", 1f),
            ("Уверенность", 0.8f),
            ("Инициатор", 1f),
            ("Инструмент", 0.9f),
            ("Область", 0.9f),
            ("Что найдено", 1.2f),
            ("Подробности", 1.6f)
        ],
        ctx.SuspiciousFindings.Select(f => new[]
        {
            f.TimestampText,
            f.ActionKindText,
            $"{f.AssessmentText} / {f.SeverityText}",
            f.ConfidenceText,
            f.InitiatorText,
            f.PossibleToolText,
            f.AreaText,
            f.Finding,
            f.Details
        }));
    }

    private static void AppendCleanupSection(ColumnDescriptor column, ForensicReportContext ctx, bool pageBreakBefore)
    {
        if (pageBreakBefore)
        {
            column.Item().PageBreak();
        }

        SectionTitle(column, "3. Все признаки очистки");
        if (ctx.Result.CleanupFindings.Count == 0)
        {
            column.Item().Text(T("Записей не найдено."));
            return;
        }

        AddDataTable(column,
        [
            ("Дата и время", 1.1f),
            ("Тип действия", 0.8f),
            ("Статус", 0.8f),
            ("Инициатор", 1f),
            ("Инструмент", 0.9f),
            ("Уверенность", 0.7f),
            ("Риск", 0.6f),
            ("Область", 0.8f),
            ("Что найдено", 1.2f),
            ("Подробности", 1.6f)
        ],
        ctx.Result.CleanupFindings
            .OrderByDescending(x => x.TimestampUtc)
            .Select(f => new[]
            {
                f.TimestampText,
                f.ActionKindText,
                f.AssessmentText,
                f.InitiatorText,
                f.PossibleToolText,
                f.ConfidenceText,
                f.SeverityText,
                f.AreaText,
                f.Finding,
                f.Details
            }));
    }

    private static void AppendDevicesSection(ColumnDescriptor column, ForensicReportContext ctx, bool pageBreakBefore)
    {
        if (pageBreakBefore)
        {
            column.Item().PageBreak();
        }

        SectionTitle(column, "4. USB-устройства");
        AddDataTable(column,
        [
            ("Тип", 1f),
            ("Имя устройства", 1.4f),
            ("Производитель", 1f),
            ("Модель", 1f),
            ("VID/PID", 0.7f),
            ("Серийный номер", 0.9f),
            ("Подключение", 1.1f),
            ("Последняя активность", 1.1f),
            ("Отключение", 1.1f),
            ("Системный ID", 1.7f)
        ],
        ctx.Result.Devices.Select(d => new[]
        {
            d.CategoryText,
            d.DisplayName,
            d.ManufacturerText,
            d.ModelText,
            d.VidPidText,
            d.SerialText,
            d.FirstConnectedText,
            d.LastSeenText,
            d.LastDisconnectedText,
            d.DeviceInstanceId
        }));
    }

    private static void AppendDossiersSection(ColumnDescriptor column, ForensicReportContext ctx, bool pageBreakBefore)
    {
        if (pageBreakBefore)
        {
            column.Item().PageBreak();
        }

        SectionTitle(column, "5. Досье устройств");

        for (var index = 0; index < ctx.ReportableDevices.Count; index++)
        {
            if (index > 0)
            {
                column.Item().PageBreak();
            }

            var device = ctx.ReportableDevices[index];
            column.Item().Background(Colors.Blue.Lighten5).Padding(8).Column(block =>
            {
                block.Item().Text(T(device.DisplayName)).SemiBold().FontSize(11);
                block.Item().Text(T($"{device.CategoryText}  |  {device.SourceText}")).FontSize(8).FontColor(Colors.Grey.Darken2);
            });

            AddKeyValueGrid(column,
            [
                ("Назначение", device.UserMeaning),
                ("Производитель", device.ManufacturerText),
                ("Модель", device.ModelText),
                ("VID/PID", device.VidPidText),
                ("Серийный номер", device.SerialText),
                ("Container ID", device.ContainerId),
                ("Подключали", device.FirstConnectedText),
                ("Последняя активность", device.LastSeenText),
                ("Отключали", device.LastDisconnectedText),
                ("Пояснение по датам", device.DateConfidenceText),
                ("Расположение", device.LocationDisplayText),
                ("Буквы дисков", device.DriveLetters),
                ("Подключено сейчас", device.IsCurrentlyConnected ? "да" : "нет"),
                ("Системный ID", device.DeviceInstanceId)
            ]);

            var correlations = ForensicReportContext.GetCorrelationEvidence(ctx.Result, device).ToArray();
            if (correlations.Length > 0)
            {
                SubTitle(column, "Корреляция");
                AddDataTable(column,
                    [("Уверенность", 0.8f), ("Описание", 4.2f)],
                    correlations.Select(c => new[] { c.EventId, c.SummaryText }));
            }

            var related = ForensicReportContext.GetRelatedEvidence(ctx.Result, device).ToArray();
            SubTitle(column, $"Связанные доказательства ({related.Length})");
            if (related.Length == 0)
            {
                column.Item().Text(T("Связанных записей не найдено.")).FontColor(Colors.Grey.Darken1);
            }
            else
            {
                AddDataTable(column,
                [
                    ("Дата и время", 1.2f),
                    ("Категория", 1.1f),
                    ("Источник", 1.1f),
                    ("Событие", 0.7f),
                    ("Описание", 2.9f)
                ],
                related.Select(e => new[]
                {
                    e.TimestampText,
                    e.EvidenceCategoryText,
                    e.SourceText,
                    e.EventId,
                    e.SummaryText
                }));
            }
        }
    }

    private static void AppendEvidenceSection(ColumnDescriptor column, ForensicReportContext ctx, bool pageBreakBefore)
    {
        if (pageBreakBefore)
        {
            column.Item().PageBreak();
        }

        SectionTitle(column, "6. Журнал доказательств и хронология");
        column.Item().Text(T("Полная временная шкала всех собранных записей (от новых к старым)."))
            .FontSize(8)
            .FontColor(Colors.Grey.Darken2);

        AddDataTable(column,
        [
            ("Дата и время", 1.2f),
            ("Категория", 1f),
            ("Источник", 1f),
            ("Событие", 0.7f),
            ("Устройство", 1.2f),
            ("Описание", 1.8f),
            ("Пояснение", 1.8f)
        ],
        ctx.Timeline.Select(e => new[]
        {
            e.TimestampText,
            e.EvidenceCategoryText,
            e.SourceText,
            e.EventId,
            T(e.DeviceHint, 220),
            T(e.Summary, 700),
            T(e.UserExplanation, 700)
        }));
    }

    private static void AppendWarningsSection(ColumnDescriptor column, ForensicReportContext ctx, bool pageBreakBefore)
    {
        if (pageBreakBefore)
        {
            column.Item().PageBreak();
        }

        SectionTitle(column, "7. Предупреждения и ограничения сбора");
        if (ctx.Result.SourceWarnings.Count == 0)
        {
            column.Item().Text(T("Предупреждений нет — все основные источники прочитаны успешно."));
            return;
        }

        AddDataTable(column,
            [("№", 0.3f), ("Предупреждение", 4.7f)],
            ctx.Result.SourceWarnings.Select((warning, index) => new[]
            {
                (index + 1).ToString(),
                warning
            }));
    }

    private static void AppendMethodologySection(ColumnDescriptor column, bool pageBreakBefore)
    {
        if (pageBreakBefore)
        {
            column.Item().PageBreak();
        }

        SectionTitle(column, "8. Источники данных");
        AddDataTable(column,
            [("Источник", 1.2f), ("Описание", 3.8f)],
            new[]
            {
                new[] { "Реестр Windows", "USB, USBSTOR, SCSI, WPD, MountedDevices." },
                new[] { "setupapi.dev.log", "Установка и удаление устройств." },
                new[] { "Журналы Windows", "System, Security, DeviceSetupManager, DriverFrameworks-UserMode." },
                new[] { "Корп. защита USB", "Журнал контроля USB (если установлен)." },
                new[] { "Пользовательские артефакты", "Recent, LNK, Jump Lists, MountPoints2, MRU." },
                new[] { "Offline-профили", "NTUSER.DAT и UsrClass.dat (при доступе)." },
                new[] { "Prefetch / Amcache", "Следы запуска и использования." },
                new[] { "Корреляция", "Сопоставление по VID/PID, серийному номеру и Instance ID." }
            });
    }

    private static void AppendExternalUtilitiesSection(
        ColumnDescriptor column,
        ExternalUtilityReportSnapshot snapshot,
        bool pageBreakBefore)
    {
        if (pageBreakBefore)
        {
            column.Item().PageBreak();
        }

        SectionTitle(column, "9. Сторонние утилиты");
        column.Item().Text(T(
                $"Снимок: {DateDisplay.FormatMoscow(snapshot.CapturedAtUtc)}; утилита: {snapshot.UtilityName ?? "не указана"}"))
            .FontSize(8)
            .FontColor(Colors.Grey.Darken2);

        if (snapshot.HistoricalLaunches.Count > 0)
        {
            SubTitle(column, "Исторические запуски USB-утилит");
            AddDataTable(column,
            [
                ("Дата", 1.1f),
                ("Утилита", 1f),
                ("Источник", 1.1f),
                ("Описание", 2.3f)
            ],
            snapshot.HistoricalLaunches.Select(x => new[]
            {
                x.TimestampText,
                x.ToolName,
                x.Source,
                T(x.Summary, 300)
            }));
        }

        if (snapshot.Rows.Count > 0)
        {
            SubTitle(column, "Считанные строки из окна утилиты");
            AddDataTable(column,
            [
                ("Раздел", 1.1f),
                ("Запись", 1.2f),
                ("Данные", 1.8f),
                ("Разбор", 2.4f)
            ],
            snapshot.Rows.Select(x => new[]
            {
                x.SectionTitle,
                x.PrimaryText,
                T(x.DetailsText, 260),
                T(x.AnalysisText, 500)
            }));
        }
    }

    private static void SectionTitle(ColumnDescriptor column, string title)
    {
        column.Item().PaddingTop(4).Background(Colors.Grey.Lighten3).Border(0.5f).BorderColor(Colors.Grey.Lighten1)
            .PaddingVertical(5).PaddingHorizontal(8)
            .Text(T(title)).SemiBold().FontSize(SectionFont);
    }

    private static void SubTitle(ColumnDescriptor column, string title)
    {
        column.Item().PaddingTop(6).Text(T(title)).SemiBold().FontSize(9.5f);
    }

    private static void StatBox(RowDescriptor row, string label, string value)
    {
        row.RelativeItem().Border(0.5f).BorderColor(Colors.Grey.Lighten1).Background(Colors.White).Padding(6).Column(box =>
        {
            box.Item().Text(T(label)).FontSize(7.5f).FontColor(Colors.Grey.Darken2);
            box.Item().Text(T(value)).SemiBold().FontSize(11);
        });
    }

    private static void AddKeyValueGrid(ColumnDescriptor column, IReadOnlyList<(string Key, string? Value)> pairs)
    {
        column.Item().PaddingTop(4).Table(table =>
        {
            table.ColumnsDefinition(columns =>
            {
                columns.RelativeColumn(1.1f);
                columns.RelativeColumn(1.9f);
                columns.RelativeColumn(1.1f);
                columns.RelativeColumn(1.9f);
            });

            for (var index = 0; index < pairs.Count; index += 2)
            {
                WriteKeyCell(table, pairs[index].Key);
                WriteValueCell(table, pairs[index].Value);

                if (index + 1 < pairs.Count)
                {
                    WriteKeyCell(table, pairs[index + 1].Key);
                    WriteValueCell(table, pairs[index + 1].Value);
                }
                else
                {
                    WriteKeyCell(table, "");
                    WriteValueCell(table, "");
                }
            }
        });
    }

    private static void WriteKeyCell(TableDescriptor table, string key)
    {
        table.Cell().Element(cell => StyleKeyValueCell(cell, header: true)).Text(T(key)).SemiBold().FontSize(8);
    }

    private static void WriteValueCell(TableDescriptor table, string? value)
    {
        table.Cell().Element(cell => StyleKeyValueCell(cell, header: false)).Text(T(value)).FontSize(8);
    }

    private static IContainer StyleKeyValueCell(IContainer cell, bool header) =>
        cell.Border(0.5f)
            .BorderColor(Colors.Grey.Lighten2)
            .Background(header ? Colors.Grey.Lighten4 : Colors.White)
            .Padding(4);

    private static void AddDataTable(
        ColumnDescriptor column,
        IReadOnlyList<(string Header, float Weight)> columns,
        IEnumerable<string[]> rows)
    {
        var materializedRows = rows.ToArray();
        if (materializedRows.Length == 0)
        {
            column.Item().Text(T("Нет данных.")).FontColor(Colors.Grey.Darken1);
            return;
        }

        column.Item().PaddingTop(2).PaddingBottom(4).Table(table =>
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
                    header.Cell().Element(HeaderCell).Text(T(columnDef.Header)).SemiBold().FontSize(HeaderFont);
                }
            });

            for (var rowIndex = 0; rowIndex < materializedRows.Length; rowIndex++)
            {
                var row = materializedRows[rowIndex];
                var zebra = rowIndex % 2 == 0 ? Colors.White : Colors.Grey.Lighten5;

                for (var index = 0; index < columns.Count; index++)
                {
                    var value = index < row.Length ? row[index] : "";
                    table.Cell().Element(cell => BodyCell(cell, zebra)).Text(T(value, 900)).FontSize(BodyFont);
                }
            }
        });
    }

    private static IContainer HeaderCell(IContainer container) =>
        container.Background(Colors.Grey.Lighten3)
            .Border(0.5f)
            .BorderColor(Colors.Grey.Lighten1)
            .Padding(4);

    private static IContainer BodyCell(IContainer container, string background) =>
        container.Background(background)
            .Border(0.5f)
            .BorderColor(Colors.Grey.Lighten2)
            .Padding(4);

    private static string T(string? value, int maxLength = 4000) => ReportText.ForPdf(value, maxLength);
}
