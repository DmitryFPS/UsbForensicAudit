using System.IO;
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
        using var output = File.Create(path);
        Generate(output, ctx);
    }

    /// <summary>Пишет отчёт в поток: тесты проверяют содержимое без записи на диск.</summary>
    public static void Generate(Stream output, ForensicReportContext ctx)
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
                            if (!ctx.Case.IsEmpty)
                            {
                                left.Item().Text(T(string.Join("  |  ", ctx.Case.DisplayFields().Select(f => $"{f.Label}: {f.Value}"))))
                                    .FontSize(8).FontColor(Colors.Blue.Darken2);
                            }
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
                    AppendNetworkSection(column, ctx, pageBreakBefore: true);
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
        }).GeneratePdf(output);
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
            ("Права администратора", result.IsAdministrator ? "да" : "нет"),
            ("Область отчёта", "USB/Type-C, включая встроенные устройства внутренней USB-шины")
        ]);

        column.Item().PaddingTop(2).Text(T(result.OsInstallGraceNote)).FontSize(7.5f).FontColor(Colors.Grey.Darken2);
        column.Item().Text(T("ОЗУ и внутренние SATA/NVMe-накопители не относятся к USB и в отчёт не включаются."))
            .FontSize(7.5f).FontColor(Colors.Grey.Darken2);
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
            StatBox(row, "Физических устройств", ctx.Counts.PhysicalDevices.ToString());
            StatBox(row, "Записей в источниках", ctx.Counts.RegistryRecords.ToString());
            StatBox(row, "USB-доказательств", ctx.Timeline.Count.ToString());
            StatBox(row, "Признаков очистки", ctx.CleanupFindings.Count.ToString());
            StatBox(row, "Подозрительных", ctx.SuspiciousCount.ToString());
            StatBox(row, "Требуют внимания", ctx.AttentionCount.ToString());
            StatBox(row, "Высокий риск", ctx.HighRiskCount.ToString());
            StatBox(row, "Предупреждений", ctx.Result.SourceWarnings.Count.ToString());
            StatBox(row, "Точные даты",
                $"{ctx.Result.Coverage.ExactDateCoveragePercent:0.##}%");
        });

        column.Item().PaddingTop(4).Text(T(ctx.Counts.Describe())).FontSize(8).FontColor(Colors.Grey.Darken2);
        column.Item().PaddingTop(4).Text(T(ctx.ActivityVerdict())).FontSize(8).FontColor(Colors.Grey.Darken2);
        column.Item().PaddingTop(4).Text(T(ctx.TransferVerdict())).FontSize(8).FontColor(Colors.Grey.Darken2);
        column.Item().PaddingTop(4).Text(T(ctx.Exfiltration.Verdict())).FontSize(8).FontColor(Colors.Grey.Darken2);
        column.Item().PaddingTop(4).Text(T(UsbExecutableHashCollector.Describe(ctx.UsbExecutableHashes))).FontSize(8).FontColor(Colors.Grey.Darken2);
        column.Item().PaddingTop(4).Text(T(ctx.Mitre.Verdict())).FontSize(8).FontColor(Colors.Grey.Darken2);
        if (ctx.PolicySummary.PolicyDefined)
        {
            column.Item().PaddingTop(4).Text(T(ctx.PolicySummary.Verdict())).FontSize(8).FontColor(Colors.Grey.Darken2);
        }
        column.Item().PaddingTop(4).Text(T(ctx.NetworkSummary.Describe())).FontSize(8).FontColor(Colors.Grey.Darken2);

        SubTitle(column, "Покрытие источников");
        AddDataTable(column,
            [
                ("Источник", 1.5f),
                ("Статус", 0.7f),
                ("Записей", 0.6f),
                ("Лимит", 0.7f),
                ("Ошибка / ограничение", 2.5f)
            ],
            ctx.Result.Coverage.Sources.Select(source => new[]
            {
                source.Source,
                source.Status,
                source.Count.ToString(),
                source.Capped
                    ? source.Limit > 0 ? source.Limit.ToString() : "достигнут"
                    : "нет",
                source.Error
            }));

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
        column.Item().PaddingBottom(4).Text(T(ctx.CleanupVerdict()));
        if (ctx.SuspiciousFindings.Count == 0)
        {
            AppendAttentionTable(column, ctx);
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
        AppendAttentionTable(column, ctx);
    }

    /// <summary>
    /// Запуск утилиты работы с USB и наличие средства удаления следов не
    /// доказывают очистку, поэтому в таблицу подозрительных записей не попадают.
    /// Без отдельной таблицы раздел об инцидентах выглядел пустым.
    /// </summary>
    private static void AppendAttentionTable(ColumnDescriptor column, ForensicReportContext ctx)
    {
        if (ctx.AttentionFindings.Count == 0)
        {
            return;
        }

        SubTitle(column, "Требуют внимания");
        AddDataTable(column,
        [
            ("Дата и время", 1.2f),
            ("Тип действия", 0.9f),
            ("Риск", 0.7f),
            ("Инициатор", 1f),
            ("Инструмент", 0.9f),
            ("Что найдено", 1.4f),
            ("Подробности", 2f)
        ],
        ctx.AttentionFindings.Select(f => new[]
        {
            f.TimestampText,
            f.ActionKindText,
            f.SeverityText,
            f.InitiatorText,
            f.PossibleToolText,
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
        if (ctx.CleanupFindings.Count == 0)
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
        ctx.CleanupFindings
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
        column.Item().Text(T(
                "Показаны реальные USB/Type-C устройства, подтверждённые связанные USB-диски и остаточные следы usbflags. " +
                "Внутренние SCSI/SATA/NVMe записи без подтверждённой связи с USB исключены."))
            .FontSize(7.5f)
            .FontColor(Colors.Grey.Darken2);
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
        ctx.ReportableDevices.Select(d => new[]
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

        for (var index = 0; index < ctx.ListedDevices.Count; index++)
        {
            if (index > 0)
            {
                column.Item().PageBreak();
            }

            var device = ctx.ListedDevices[index];
            column.Item().Background(Colors.Blue.Lighten5).Padding(8).Column(block =>
            {
                block.Item().Text(T(device.DisplayName)).SemiBold().FontSize(11);
                block.Item().Text(T($"{device.CategoryText}  |  {device.SourceText}")).FontSize(8).FontColor(Colors.Grey.Darken2);
            });

            AddKeyValueGrid(column, DeviceCardModel.CompactFieldsOf(device));

            // Записи, свёрнутые в это устройство. У сопряжённого телефона это
            // перечень его услуг: по нему видно, что через соединение было
            // можно — передавать файлы, читать контакты, выходить в сеть.
            var parts = DeviceComposition.PartsOf(device, ctx.ReportableDevices);
            if (parts.Count > 0)
            {
                SubTitle(column, $"Записи Windows об этом устройстве ({parts.Count})");
                AddDataTable(column,
                    [("Имя", 1.4f), ("Что это за запись", 3.1f), ("Системный ID", 2.5f)],
                    parts.Select(part => new[]
                    {
                        part.OwnDisplayName,
                        string.IsNullOrWhiteSpace(part.UserMeaning) ? part.CategoryText : part.UserMeaning,
                        part.DeviceInstanceId
                    }));
            }

            var correlations = ForensicReportContext.GetCorrelationEvidence(ctx, device).ToArray();
            if (correlations.Length > 0)
            {
                SubTitle(column, "Корреляция");
                AddDataTable(column,
                    [("Уверенность", 0.8f), ("Описание", 4.2f)],
                    correlations.Select(c => new[] { c.EventId, c.SummaryText }));
            }

            var related = ForensicReportContext.GetRelatedEvidence(ctx, device).ToArray();
            SubTitle(column, $"Связанные доказательства ({related.Length})");
            if (related.Length == 0)
            {
                column.Item().Text(T("Связанных записей не найдено.")).FontColor(Colors.Grey.Darken1);
            }
            else
            {
                AddDataTable(column, DeviceCardModel.EvidenceColumns, related.Select(DeviceCardModel.EvidenceRowOf));
            }

            AppendDeviceActivity(column, ctx.GetActivity(device));
        }
    }

    /// <summary>
    /// Что делали на устройстве. В печатном отчёте список обрезан: полный
    /// перечень остаётся в окне программы и в отчёте HTML, и об этом сказано,
    /// чтобы обрезанный список не приняли за полный.
    /// </summary>
    private const int MaxActivityRowsInPdf = 150;

    private static void AppendDeviceActivity(ColumnDescriptor column, DeviceActivityHistory history)
    {
        SubTitle(column, $"Что делали на устройстве ({history.Entries.Count})");
        column.Item().Text(T(history.Verdict())).FontSize(8).FontColor(Colors.Grey.Darken2);

        if (history.Entries.Count > 0)
        {
            if (history.Entries.Count > MaxActivityRowsInPdf)
            {
                column.Item().Text(T($"В печатный отчёт вошли последние {MaxActivityRowsInPdf} действий из "
                                     + $"{history.Entries.Count}. Полный перечень — в отчёте HTML и в окне программы."))
                    .FontSize(8).FontColor(Colors.Orange.Darken2);
            }

            AddDataTable(column,
            [
                ("Когда", 1.2f),
                ("Что делали", 1.6f),
                ("Папка или файл", 2.6f),
                ("Кто", 1.1f),
                ("Почему отнесено к устройству", 2f)
            ],
            history.Entries.Take(MaxActivityRowsInPdf).Select(x => new[]
            {
                x.TimestampText, x.KindText, x.PathText, x.UserText, x.LinkText
            }));
        }

        SubTitle(column, $"Перенос файлов ({history.CopyIndications.Count})");
        column.Item().Text(T(history.CopyVerdict())).FontSize(8).FontColor(Colors.Grey.Darken2);
        if (history.CopyIndications.Count == 0)
        {
            return;
        }

        AddDataTable(column,
        [
            ("Имя файла", 1.6f),
            ("Куда перенесли", 1.4f),
            ("Надёжность", 1f),
            ("Путь на устройстве", 2.2f),
            ("Путь на внутреннем диске", 2.2f),
            ("Когда виден на диске", 1.2f)
        ],
        history.CopyIndications.Select(x => new[]
        {
            x.FileName, x.DirectionText, x.ConfidenceText, x.PathOnDevice, x.LocalPath, x.SeenLocallyText
        }));
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
            ("Сила / уверенность", 1f),
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
            $"{e.EvidenceStrength} / {e.Confidence}",
            e.EventId,
            T(e.DeviceHint, 220),
            T(e.Summary, 700),
            T(e.UserExplanation, 700)
        }));
    }

    /// <summary>
    /// Сколько обращений и сеансов печатается по одной связи. У сайтов история
    /// браузера даёт тысячи строк, и печать их целиком превращает отчёт в том,
    /// который никто не читает. Обрезка названа прямо, чтобы её не приняли за
    /// полный перечень.
    /// </summary>
    private const int MaxNetworkRowsInPdf = 60;

    private static void AppendNetworkSection(ColumnDescriptor column, ForensicReportContext ctx, bool pageBreakBefore)
    {
        if (pageBreakBefore)
        {
            column.Item().PageBreak();
        }

        SectionTitle(column, "7. Сетевые подключения и куда по ним ходили");
        column.Item().Text(T(ctx.NetworkSummary.Describe())).FontSize(8).FontColor(Colors.Grey.Darken2);
        if (ctx.NetworkConnections.Count == 0)
        {
            return;
        }

        AddDataTable(column,
        [
            ("Как связывались", 1.1f),
            ("С чем именно", 1.6f),
            ("Кто начал", 1f),
            ("Что нашлось", 1f),
            ("Первое подключение", 1.2f),
            ("Последнее подключение", 1.2f),
            ("Чем защищено", 1.3f),
            ("Простыми словами", 2.6f)
        ],
        ctx.NetworkConnections.Select(x => new[]
        {
            x.KindText,
            x.TargetText,
            x.DirectionText,
            x.ActivityText,
            x.FirstSeenText,
            x.LastSeenText,
            x.SecurityText,
            T(x.DetailsText, 700)
        }));

        foreach (var connection in ctx.NetworkConnections.Where(x => x.Visits.Count > 0 || x.Sessions.Count > 0))
        {
            AppendNetworkConnectionCard(column, connection);
        }
    }

    private static void AppendNetworkConnectionCard(ColumnDescriptor column, NetworkConnectionRecord connection)
    {
        SubTitle(column, $"{connection.KindText}: {connection.TargetText}");
        AddDataTable(column,
            [("Сведение", 1.4f), ("Значение", 3.6f)],
            NetworkConnectionFacts.Rows(connection).Select(x => new[] { x.Name, T(x.Value, 700) }));

        if (connection.Visits.Count > 0)
        {
            SubTitle(column, $"Куда ходили ({connection.Visits.Count})");
            if (connection.Visits.Count > MaxNetworkRowsInPdf)
            {
                column.Item().Text(T($"В печатный отчёт вошли первые {MaxNetworkRowsInPdf} обращений из "
                                     + $"{connection.Visits.Count}. Полный перечень — в отчёте HTML и в окне программы."))
                    .FontSize(8).FontColor(Colors.Orange.Darken2);
            }

            AddDataTable(column,
            [
                ("Когда", 1.2f),
                ("Что делали", 1.4f),
                ("Папка, адрес или узел", 2.6f),
                ("Кто", 1f),
                ("Сколько раз", 1f),
                ("Откуда взято", 1.4f)
            ],
            connection.Visits.Take(MaxNetworkRowsInPdf).Select(x => new[]
            {
                x.WhenText, x.KindText, T(x.TargetText, 400), x.UserText, x.CountText, x.SourceText
            }));
        }

        if (connection.Sessions.Count == 0)
        {
            return;
        }

        SubTitle(column, $"Сеансы связи ({connection.Sessions.Count})");
        if (connection.Sessions.Count > MaxNetworkRowsInPdf)
        {
            column.Item().Text(T($"В печатный отчёт вошли первые {MaxNetworkRowsInPdf} сеансов из "
                                 + $"{connection.Sessions.Count}. Полный перечень — в отчёте HTML и в окне программы."))
                .FontSize(8).FontColor(Colors.Orange.Darken2);
        }

        AddDataTable(column,
        [
            ("Подключение", 1.2f),
            ("Отключение", 1.2f),
            ("Сколько держалось", 1f),
            ("Чем закончилось", 2f),
            ("Подробности", 2f)
        ],
        connection.Sessions.Take(MaxNetworkRowsInPdf).Select(x => new[]
        {
            x.StartedText, x.EndedText, x.DurationText, T(x.OutcomeText, 300), T(x.ReasonText, 400)
        }));
    }

    private static void AppendWarningsSection(ColumnDescriptor column, ForensicReportContext ctx, bool pageBreakBefore)
    {
        if (pageBreakBefore)
        {
            column.Item().PageBreak();
        }

        SectionTitle(column, "8. Предупреждения и ограничения сбора");
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

        SectionTitle(column, "9. Источники данных");
        AddDataTable(column,
            [("Источник", 1.2f), ("Описание", 3.8f)],
            new[]
            {
                new[] { "Реестр Windows", "USB, USBSTOR, SCSI, WPD, MountedDevices, DeviceMigration и ControlSet." },
                new[] { "SetupAPI", "Текущий и архивные setupapi.dev.log, включая доступные VSS-копии." },
                new[] { "Журналы Windows", "System, Security, Kernel-PnP, Storage-ClassPnP, Partition, WPD-MTP и DeviceSetupManager." },
                new[] { "Корп. защита USB", "Журнал контроля USB (если установлен)." },
                new[] { "Пользовательские артефакты", "Recent, PIDL/MRU, LNK, Jump Lists, Shellbags, MountPoints2 и Recycle Bin." },
                new[] { "Offline-профили", "NTUSER.DAT и UsrClass.dat (при доступе)." },
                new[] { "Исполнение", "Prefetch, Amcache, Shimcache, PCA и BAM/DAM с явной силой доказательства." },
                new[] { "Исторические источники", "Windows.old, существующие VSS и transaction-log provenance без заявления о полном replay." },
                new[] { "Корреляция", "ContainerID, serial, topology, тома/VSN и защита от слияния только по VID/PID." },
                new[] { "Покрытие", "Статус, лимиты и ошибки каждого сборщика; доля canonical-устройств с точной датой." },
                new[] { "Сети", "Список сетей и подписи в реестре, параметры подключений, профили Wi-Fi, сопряжения Bluetooth." },
                new[] { "Журналы сетей", "WLAN-AutoConfig, NetworkProfile, SMBClient, TerminalServices, RasClient." },
                new[] { "Куда ходили по сети", "Сетевые диски, введённые пути, ярлыки, списки переходов, история браузеров и загрузки." }
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

        SectionTitle(column, "10. Сторонние утилиты");
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

    private static void SectionTitle(ColumnDescriptor column, string title) =>
        PdfComponents.BoxedTitle(column, T(title), SectionFont, paddingVertical: 5);

    private static void SubTitle(ColumnDescriptor column, string title) =>
        PdfComponents.PlainTitle(column, T(title), 9.5f, paddingTop: 6);

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
