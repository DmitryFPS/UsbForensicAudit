using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace UsbForensicAudit;

/// <summary>
/// Аналитическая записка — рассказ о картине в целом, а не свалка таблиц.
///
/// Полный отчёт отвечает на вопрос «что именно нашлось в каждом источнике» и
/// нужен для проверки выводов. Записка отвечает на вопрос следователя: какие
/// устройства подключали, куда машина ходила по сети, что делали на устройствах
/// и в каком порядке всё происходило. Формат повторяет записку аналитика:
/// шапка с метаданными, компактная таблица устройств, досье в одну строку на
/// устройство, сетевая активность, действия пользователя и общая хронология.
/// </summary>
internal static class AnalystNotePdfReport
{
    private const float BodyFont = 9f;
    private const float SectionFont = 13f;
    private const int MaxSessionRows = 25;
    private const int MaxActivityPerDevice = 12;
    private const int MaxChronologyRows = 200;

    public static void Generate(string path, ForensicReportContext ctx)
    {
        var result = ctx.Result;

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
                    header.Item().Text(T("FORENSIC-ОТЧЁТ")).Bold().FontSize(16);
                    header.Item().Text(T("Подключаемые устройства и сетевая активность"))
                        .FontSize(10).FontColor(Colors.Grey.Darken2);
                    header.Item().PaddingTop(4).LineHorizontal(1f).LineColor(Colors.Grey.Darken3);
                });

                page.Content().PaddingTop(8).Column(column =>
                {
                    column.Spacing(5);
                    AppendMetadata(column, ctx);
                    AppendDevicesSection(column, ctx);
                    AppendDeviceDetails(column, ctx);
                    AppendNetworkSection(column, ctx);
                    AppendUserActions(column, ctx);
                    AppendChronology(column, ctx);
                    AppendConclusions(column, ctx);
                });

                page.Footer().AlignCenter().Text(text =>
                {
                    text.DefaultTextStyle(x => x.FontSize(7.5f)
                        .FontFamily(PdfFontHelper.DefaultFamily)
                        .FontColor(Colors.Grey.Darken1));
                    text.Span(T($"Сформировано: {DateDisplay.FormatMoscow(DateTimeOffset.UtcNow)} — все даты МСК — стр. "));
                    text.CurrentPageNumber();
                    text.Span(" / ");
                    text.TotalPages();
                });
            });
        }).GeneratePdf(path);
    }

    // ------------------------------------------------------------------
    // Шапка: объект, пользователь, ОС, период аудита.
    // ------------------------------------------------------------------
    private static void AppendMetadata(ColumnDescriptor column, ForensicReportContext ctx)
    {
        var result = ctx.Result;
        var auditPeriod = $"{DateDisplay.FormatMoscow(result.StartedAtUtc)} — {DateDisplay.FormatMoscow(result.FinishedAtUtc)}";

        column.Item().Border(0.75f).BorderColor(Colors.Grey.Lighten1).Padding(8).Column(box =>
        {
            box.Spacing(1.5f);
            MetaRow(box, "Объект", result.ComputerName);
            MetaRow(box, "Пользователь", result.UserName);
            MetaRow(box, "ОС", result.WindowsVersion);
            MetaRow(box, "Установка ОС", result.OsInstalledAtText);
            MetaRow(box, "Аудит", auditPeriod);
            MetaRow(box, "Права администратора", result.IsAdministrator ? "да" : "нет");
            MetaRow(box, "Источники", $"реестр и журналы Windows, {ctx.Timeline.Count} USB-доказательств, "
                                       + $"{ctx.NetworkConnections.Count} сетевых связей");
        });
    }

    private static void MetaRow(ColumnDescriptor box, string key, string? value)
    {
        box.Item().Row(row =>
        {
            row.ConstantItem(150).Text(T(key)).SemiBold().FontColor(Colors.Grey.Darken3);
            row.RelativeItem().Text(T(value));
        });
    }

    // ------------------------------------------------------------------
    // 1. Подключаемые устройства — компактная таблица.
    // ------------------------------------------------------------------
    private static void AppendDevicesSection(ColumnDescriptor column, ForensicReportContext ctx)
    {
        SectionTitle(column, "1. Подключаемые устройства");

        if (ctx.ListedDevices.Count == 0)
        {
            column.Item().Text(T("Подключаемых устройств в собранных данных не найдено.")).Italic();
            return;
        }

        AddTable(column,
            [("№", 0.35f), ("Устройство", 1.9f), ("Канал", 1.05f), ("ID", 0.9f), ("Serial/MAC", 1.55f), ("Первое", 1.05f), ("Последнее", 1.05f)],
            ctx.ListedDevices.Select((device, index) => new[]
            {
                (index + 1).ToString(),
                device.ModelText,
                device.TransportDisplayText,
                device.VidPidText,
                device.SerialText,
                device.FirstConnectedText,
                device.LastSeenText
            }));
    }

    // ------------------------------------------------------------------
    // 1.1. Детали по устройствам — одна строка на устройство.
    // ------------------------------------------------------------------
    private static void AppendDeviceDetails(ColumnDescriptor column, ForensicReportContext ctx)
    {
        if (ctx.ListedDevices.Count == 0)
        {
            return;
        }

        SubTitle(column, "1.1. Детали по устройствам");

        foreach (var device in ctx.ListedDevices)
        {
            var parts = new List<string>();
            if (device.DriveLetters.Length > 0)
            {
                parts.Add($"тома {device.DriveLetters}");
            }

            if (device.Manufacturer.Length > 0)
            {
                parts.Add($"производитель {device.Manufacturer}");
            }

            if (device.ContainerId.Length > 0)
            {
                parts.Add($"ContainerID {device.ContainerId}");
            }

            var activity = ctx.GetActivity(device);
            parts.Add(activity.IsEmpty
                ? "следов работы с файлами не найдено"
                : $"действий с файлами: {activity.Entries.Count}");

            column.Item().Text(text =>
            {
                text.DefaultTextStyle(x => x.FontSize(BodyFont).FontFamily(PdfFontHelper.DefaultFamily));
                text.Span(T(device.ModelText)).SemiBold();
                text.Span(T($" — {string.Join(", ", parts)}."));
            });
        }

        // Одинаковый нелегитимный VID/PID у нескольких носителей — примета
        // клонов или кастомной прошивки, о которой аналитик обязан сказать.
        var sharedIds = ctx.ListedDevices
            .Where(x => x.Vid.Length > 0 && x.Pid.Length > 0)
            .GroupBy(x => $"{x.Vid}:{x.Pid}", StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .ToArray();
        foreach (var group in sharedIds)
        {
            column.Item().PaddingTop(2).Text(T(
                    $"Внимание: VID/PID {group.Key} совпадает у {group.Count()} устройств "
                    + $"({string.Join(", ", group.Select(x => x.ModelText))}) — возможен клон или кастомная прошивка."))
                .FontColor(Colors.Red.Darken2);
        }
    }

    // ------------------------------------------------------------------
    // 2. Сетевая активность: сводка связей и ключевые сеансы.
    // ------------------------------------------------------------------
    private static void AppendNetworkSection(ColumnDescriptor column, ForensicReportContext ctx)
    {
        SectionTitle(column, "2. Сетевая активность");

        if (ctx.NetworkConnections.Count == 0)
        {
            column.Item().Text(T("Сетевых связей в собранных данных не найдено.")).Italic();
            return;
        }

        SubTitle(column, "2.1. Сетевые подключения (сводка)");
        AddTable(column,
            [("Тип", 1.0f), ("Объект", 1.8f), ("Направление", 1.3f), ("Первое", 1.2f), ("Последнее", 1.2f)],
            ctx.NetworkConnections.Select(connection => new[]
            {
                connection.KindText,
                connection.NameText.Length > 0 ? connection.NameText : connection.AddressText,
                connection.DirectionText,
                connection.FirstSeenText,
                connection.LastSeenText
            }));

        var sessions = ctx.NetworkConnections
            .SelectMany(connection => connection.Sessions.Select(session => (Connection: connection, Session: session)))
            .Where(x => x.Session.StartedUtc is not null)
            .OrderByDescending(x => x.Session.StartedUtc)
            .Take(MaxSessionRows)
            .ToArray();
        if (sessions.Length > 0)
        {
            SubTitle(column, $"2.2. Сетевые сеансы (последние {sessions.Length})");
            AddTable(column,
                [("Связь", 1.5f), ("Тип", 0.9f), ("Подключение", 1.2f), ("Отключение", 1.2f), ("Длительность", 0.9f), ("Итог", 1.8f)],
                sessions.Select(x => new[]
                {
                    x.Connection.NameText.Length > 0 ? x.Connection.NameText : x.Connection.AddressText,
                    x.Connection.KindText,
                    x.Session.StartedText,
                    x.Session.EndedText,
                    x.Session.DurationText,
                    x.Session.OutcomeText
                }));
        }
    }

    // ------------------------------------------------------------------
    // 3. Действия пользователя на устройствах.
    // ------------------------------------------------------------------
    private static void AppendUserActions(ColumnDescriptor column, ForensicReportContext ctx)
    {
        SectionTitle(column, "3. Действия пользователя на устройствах");

        var withActivity = ctx.DevicesWithActivity().ToArray();
        if (withActivity.Length == 0)
        {
            column.Item().Text(T(ctx.ActivityVerdict())).Italic();
            return;
        }

        column.Item().Text(T(ctx.ActivityVerdict())).FontColor(Colors.Grey.Darken2);

        foreach (var (device, history) in withActivity)
        {
            SubTitle(column, device.ModelText);
            var entries = history.Entries
                .OrderBy(x => x.TimestampUtc)
                .ToArray();
            foreach (var entry in entries.Take(MaxActivityPerDevice))
            {
                column.Item().PaddingLeft(10).Text(T(
                    $"{DateDisplay.FormatMoscow(entry.TimestampUtc)} — {entry.KindText}: {entry.PathText}"));
            }

            if (entries.Length > MaxActivityPerDevice)
            {
                column.Item().PaddingLeft(10).Text(T(
                        $"…и ещё {entries.Length - MaxActivityPerDevice} действий — полный список в полном отчёте."))
                    .FontColor(Colors.Grey.Darken1);
            }
        }

        var transfers = ctx.Transfers().ToArray();
        if (transfers.Length > 0)
        {
            SubTitle(column, "Признаки переноса файлов");
            column.Item().Text(T(ctx.TransferVerdict())).FontColor(Colors.Grey.Darken2);
        }
    }

    // ------------------------------------------------------------------
    // 4. Полная хронология: устройства, сеть и очистка в одном потоке.
    // ------------------------------------------------------------------
    private static void AppendChronology(ColumnDescriptor column, ForensicReportContext ctx)
    {
        SectionTitle(column, "4. Полная хронология");

        var events = BuildChronology(ctx);
        if (events.Count == 0)
        {
            column.Item().Text(T("Датированных событий для хронологии не набралось.")).Italic();
            return;
        }

        column.Item().Text(T(
                "Одна лента: подключения устройств, сетевые события, действия с файлами и признаки очистки — "
                + "в порядке времени. Так видно, что за чем следовало."))
            .FontColor(Colors.Grey.Darken2);

        foreach (var entry in events.Take(MaxChronologyRows))
        {
            column.Item().Text(text =>
            {
                text.DefaultTextStyle(x => x.FontSize(BodyFont).FontFamily(PdfFontHelper.DefaultFamily));
                text.Span(T(DateDisplay.FormatMoscow(entry.At))).SemiBold();
                text.Span(T($" — {entry.Text}"));
            });
        }

        if (events.Count > MaxChronologyRows)
        {
            column.Item().Text(T(
                    $"…и ещё {events.Count - MaxChronologyRows} событий — полная лента в полном отчёте."))
                .FontColor(Colors.Grey.Darken1);
        }
    }

    private static List<(DateTimeOffset At, string Text)> BuildChronology(ForensicReportContext ctx)
    {
        var events = new List<(DateTimeOffset At, string Text)>();
        var result = ctx.Result;

        if (result.OsInstalledAtUtc is { } installed)
        {
            events.Add((installed, "Установка Windows."));
        }

        foreach (var device in ctx.ListedDevices)
        {
            if (device.FirstConnectedUtc is { } first)
            {
                events.Add((first, $"Устройство: {device.ModelText}, первое подключение."));
            }

            if (device.LastSeenUtc is { } last && last != device.FirstConnectedUtc)
            {
                events.Add((last, $"Устройство: {device.ModelText}, последняя активность."));
            }
        }

        foreach (var connection in ctx.NetworkConnections)
        {
            var label = connection.NameText.Length > 0 ? connection.NameText : connection.AddressText;
            if (connection.FirstSeenUtc is { } first)
            {
                events.Add((first, $"{connection.KindText}: {label}, первое событие."));
            }

            foreach (var session in connection.Sessions)
            {
                if (session.StartedUtc is { } started)
                {
                    var outcome = session.OutcomeText.Length > 0 ? $" {session.OutcomeText}" : "";
                    events.Add((started, $"{connection.KindText}: {label}.{outcome}"));
                }
            }
        }

        foreach (var (device, history) in ctx.DevicesWithActivity())
        {
            foreach (var entry in history.Entries)
            {
                events.Add((entry.TimestampUtc, $"{device.ModelText}: {entry.KindText} — {entry.PathText}."));
            }
        }

        foreach (var finding in ctx.CleanupFindings)
        {
            events.Add((finding.TimestampUtc, $"Признак очистки: {finding.Finding}"));
        }

        return events
            .Where(x => x.At > DateTimeOffset.MinValue)
            .OrderBy(x => x.At)
            .ToList();
    }

    // ------------------------------------------------------------------
    // Выводы: те же вердикты, что и в остальных отчётах, — одним блоком.
    // ------------------------------------------------------------------
    private static void AppendConclusions(ColumnDescriptor column, ForensicReportContext ctx)
    {
        SectionTitle(column, "5. Выводы");
        column.Item().Text(T($"Устройства: {ctx.Counts.Describe()}"));
        column.Item().Text(T($"Сеть: {ctx.NetworkSummary.Describe()}"));
        column.Item().Text(T($"Файловая активность: {ctx.ActivityVerdict()}"));
        column.Item().Text(T($"Перенос файлов: {ctx.TransferVerdict()}"));
        column.Item().Text(T($"Очистка следов: {ctx.CleanupVerdict()}"));
        column.Item().PaddingTop(4).Text(T(
                "Записка — сжатый пересказ; исходные записи, происхождение каждой даты и полные таблицы — "
                + "в полном отчёте PDF/Excel за то же сканирование."))
            .FontSize(7.5f).FontColor(Colors.Grey.Darken1);
    }

    // ------------------------------------------------------------------
    // Местные помощники оформления.
    // ------------------------------------------------------------------
    private static void SectionTitle(ColumnDescriptor column, string title)
    {
        column.Item().PaddingTop(10).Text(T(title)).Bold().FontSize(SectionFont);
        column.Item().LineHorizontal(0.5f).LineColor(Colors.Grey.Lighten1);
    }

    private static void SubTitle(ColumnDescriptor column, string title)
    {
        column.Item().PaddingTop(5).Text(T(title)).SemiBold().FontSize(10.5f);
    }

    private static void AddTable(
        ColumnDescriptor column,
        IReadOnlyList<(string Header, float Width)> headers,
        IEnumerable<string[]> rows)
    {
        column.Item().Table(table =>
        {
            table.ColumnsDefinition(columns =>
            {
                foreach (var (_, width) in headers)
                {
                    columns.RelativeColumn(width);
                }
            });

            table.Header(headerRow =>
            {
                foreach (var (header, _) in headers)
                {
                    headerRow.Cell()
                        .Background(Colors.Grey.Lighten3)
                        .BorderBottom(0.75f).BorderColor(Colors.Grey.Darken1)
                        .PaddingVertical(2).PaddingHorizontal(3)
                        .Text(T(header)).SemiBold().FontSize(8f);
                }
            });

            foreach (var row in rows)
            {
                foreach (var cell in row)
                {
                    table.Cell()
                        .BorderBottom(0.4f).BorderColor(Colors.Grey.Lighten2)
                        .PaddingVertical(2).PaddingHorizontal(3)
                        .Text(T(cell, 400)).FontSize(8f);
                }
            }
        });
    }

    private static string T(string? value, int maxLength = 4000) => ReportText.ForPdf(value, maxLength);
}
