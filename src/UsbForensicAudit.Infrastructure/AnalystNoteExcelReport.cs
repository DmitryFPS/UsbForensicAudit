using ClosedXML.Excel;

namespace UsbForensicAudit;

/// <summary>
/// Аналитическая записка в Excel — те же разделы, что и в PDF-записке,
/// разложенные по листам: шапка с выводами, устройства с досье, сетевая
/// активность, действия пользователя и общая хронология. Содержимое строится
/// из AnalystNoteContent, поэтому PDF и Excel рассказывают одно и то же.
/// </summary>
internal static class AnalystNoteExcelReport
{
    private static readonly XLColor HeaderColor = XLColor.FromHtml("#1F4E78");
    private static readonly XLColor SectionColor = XLColor.FromHtml("#D9EAF7");
    private static readonly XLColor BorderColor = XLColor.FromHtml("#AFC4D4");
    private static readonly XLColor WarningColor = XLColor.FromHtml("#FDE2E6");
    private static readonly XLColor CaveatColor = XLColor.FromHtml("#FFF1C9");

    public static void Generate(string path, ForensicReportContext ctx)
    {
        using var workbook = new XLWorkbook();
        workbook.Properties.Title = "Аналитическая записка UsbForensicAudit";
        workbook.Properties.Subject = "Подключаемые устройства и сетевая активность — связный рассказ";
        workbook.Properties.Author = "UsbForensicAudit";
        workbook.Properties.Company = "UsbForensicAudit";
        workbook.Properties.Comments = "Все даты представлены в московском времени (МСК).";

        AddSummarySheet(workbook, ctx);
        AddDevicesSheet(workbook, ctx);
        AddNetworkSheet(workbook, ctx);
        AddUserActionsSheet(workbook, ctx);
        AddChronologySheet(workbook, ctx);

        workbook.SaveAs(path);
    }

    // ------------------------------------------------------------------
    // Лист «Записка»: шапка объекта и выводы — то, с чего читают.
    // ------------------------------------------------------------------
    private static void AddSummarySheet(XLWorkbook workbook, ForensicReportContext ctx)
    {
        var result = ctx.Result;
        var sheet = workbook.Worksheets.Add("Записка");
        ConfigureSheet(sheet);
        sheet.Column(1).Width = 26;
        sheet.Column(2).Width = 110;

        AddTitle(sheet, "Аналитическая записка",
            $"Подключаемые устройства и сетевая активность | Сформировано: {DateDisplay.FormatMoscow(DateTimeOffset.UtcNow)}", 2);

        var row = 4;
        AddSectionHeader(sheet, row++, 2, "Объект аудита");
        foreach (var (label, value) in new[]
                 {
                     ("Объект", result.ComputerName),
                     ("Пользователь", result.UserName),
                     ("ОС", result.WindowsVersion),
                     ("Установка ОС", result.OsInstalledAtText),
                     ("Аудит", $"{DateDisplay.FormatMoscow(result.StartedAtUtc)} — {DateDisplay.FormatMoscow(result.FinishedAtUtc)}"),
                     ("Права администратора", result.IsAdministrator ? "да" : "нет"),
                     ("Источники", $"реестр и журналы Windows, {ctx.Timeline.Count} USB-доказательств, {ctx.NetworkConnections.Count} сетевых связей")
                 })
        {
            AddKeyValueRow(sheet, row++, label, value);
        }

        row++;
        AddSectionHeader(sheet, row++, 2, "Выводы");
        foreach (var (label, value) in new[]
                 {
                     ("Устройства", ctx.Counts.Describe()),
                     ("Сеть", ctx.NetworkSummary.Describe()),
                     ("Файловая активность", ctx.ActivityVerdict()),
                     ("Перенос файлов", ctx.TransferVerdict()),
                     ("Очистка следов", ctx.CleanupVerdict())
                 })
        {
            AddKeyValueRow(sheet, row++, label, value, tall: true);
        }

        row++;
        sheet.Range(row, 1, row, 2).Merge();
        sheet.Cell(row, 1).Value =
            "Записка — сжатый пересказ; исходные записи, происхождение каждой даты и полные таблицы — "
            + "в полном отчёте PDF/Excel за то же сканирование.";
        sheet.Cell(row, 1).Style.Font.Italic = true;
        sheet.Cell(row, 1).Style.Alignment.WrapText = true;
        sheet.Row(row).Height = 30;
    }

    // ------------------------------------------------------------------
    // Лист «Устройства»: таблица из раздела 1 плюс досье из раздела 1.1.
    // ------------------------------------------------------------------
    private static void AddDevicesSheet(XLWorkbook workbook, ForensicReportContext ctx)
    {
        var sheet = workbook.Worksheets.Add("Устройства");
        ConfigureSheet(sheet);
        double[] widths = [5, 34, 26, 16, 26, 22, 22, 26, 70];
        for (var i = 0; i < widths.Length; i++)
        {
            sheet.Column(i + 1).Width = widths[i];
        }

        AddTitle(sheet, "1. Подключаемые устройства", "Таблица устройств и досье в одну строку на устройство", widths.Length);

        var row = 4;

        // Строк в таблице больше, чем «физических устройств» в выводах:
        // таблица доказывает полноту разбора и содержит записи шины и
        // остаточные следы. Без пояснения два числа выглядят противоречием.
        sheet.Range(row, 1, row, widths.Length).Merge();
        sheet.Cell(row, 1).Value = Clean(
            ctx.Counts.Describe()
            + " В таблице ниже перечислены все записи области аудита, включая записи шины "
            + "и остаточные следы, — их тип назван в колонке «Тип записи».");
        sheet.Cell(row, 1).Style.Font.Italic = true;
        sheet.Cell(row, 1).Style.Alignment.WrapText = true;
        sheet.Row(row).Height = 44;
        row++;

        row = AddTableHeader(sheet, row, ["№", "Устройство", "Канал", "VID/PID", "Serial/MAC", "Первое", "Последнее", "Тип записи", "Детали"]);

        var index = 0;
        foreach (var device in ctx.ListedDevices)
        {
            index++;
            string[] cells =
            [
                index.ToString(),
                device.ModelText,
                device.TransportDisplayText,
                device.VidPidText,
                device.SerialText,
                device.FirstConnectedText,
                device.LastSeenText,
                device.CategoryText,
                AnalystNoteContent.DeviceDetailLine(ctx, device)
            ];
            row = AddDataRow(sheet, row, cells);
        }

        foreach (var warning in AnalystNoteContent.SharedVidPidWarnings(ctx))
        {
            sheet.Range(row, 1, row, widths.Length).Merge();
            sheet.Cell(row, 1).Value = Clean(warning);
            sheet.Cell(row, 1).Style.Fill.BackgroundColor = WarningColor;
            sheet.Cell(row, 1).Style.Alignment.WrapText = true;
            sheet.Row(row).Height = 30;
            row++;
        }

        if (ctx.ListedDevices.Count == 0)
        {
            sheet.Cell(row, 1).Value = "Подключаемых устройств в собранных данных не найдено.";
        }
    }

    // ------------------------------------------------------------------
    // Лист «Сеть»: сводка связей и последние сеансы — раздел 2.
    // ------------------------------------------------------------------
    private static void AddNetworkSheet(XLWorkbook workbook, ForensicReportContext ctx)
    {
        var sheet = workbook.Worksheets.Add("Сеть");
        ConfigureSheet(sheet);
        double[] widths = [22, 40, 26, 22, 22, 16, 42];
        for (var i = 0; i < widths.Length; i++)
        {
            sheet.Column(i + 1).Width = widths[i];
        }

        AddTitle(sheet, "2. Сетевая активность", "Сводка связей и последние сеансы", widths.Length);

        var row = 4;
        AddSectionHeader(sheet, row++, widths.Length, "2.1. Сетевые подключения (сводка)");
        row = AddTableHeader(sheet, row, ["Тип", "Объект", "Направление", "Первое", "Последнее"]);
        foreach (var connection in ctx.NetworkConnections)
        {
            row = AddDataRow(sheet, row,
            [
                connection.KindText,
                connection.NameText.Length > 0 ? connection.NameText : connection.AddressText,
                connection.DirectionText,
                connection.FirstSeenText,
                connection.LastSeenText
            ]);
        }

        if (ctx.NetworkConnections.Count == 0)
        {
            sheet.Cell(row++, 1).Value = "Сетевых связей в собранных данных не найдено.";
        }

        var sessions = ctx.NetworkConnections
            .SelectMany(connection => connection.Sessions.Select(session => (Connection: connection, Session: session)))
            .Where(x => x.Session.StartedUtc is not null)
            .OrderByDescending(x => x.Session.StartedUtc)
            .Take(25)
            .ToArray();
        if (sessions.Length > 0)
        {
            row++;
            AddSectionHeader(sheet, row++, widths.Length, $"2.2. Сетевые сеансы (последние {sessions.Length})");
            row = AddTableHeader(sheet, row, ["Связь", "Тип", "Подключение", "Отключение", "Длительность", "", "Итог"]);
            foreach (var (connection, session) in sessions)
            {
                row = AddDataRow(sheet, row,
                [
                    connection.NameText.Length > 0 ? connection.NameText : connection.AddressText,
                    connection.KindText,
                    session.StartedText,
                    session.EndedText,
                    session.DurationText,
                    "",
                    session.OutcomeText
                ]);
            }
        }
    }

    // ------------------------------------------------------------------
    // Лист «Действия пользователя»: раздел 3 — по каждому носителю.
    // ------------------------------------------------------------------
    private static void AddUserActionsSheet(XLWorkbook workbook, ForensicReportContext ctx)
    {
        var sheet = workbook.Worksheets.Add("Действия пользователя");
        ConfigureSheet(sheet);
        double[] widths = [34, 24, 30, 80, 46];
        for (var i = 0; i < widths.Length; i++)
        {
            sheet.Column(i + 1).Width = widths[i];
        }

        AddTitle(sheet, "3. Действия пользователя на устройствах", Clean(ctx.ActivityVerdict()), widths.Length);

        var row = 4;
        row = AddTableHeader(sheet, row, ["Устройство", "Когда", "Действие", "Файл или папка", "Примечание"]);

        var withActivity = ctx.DevicesWithActivity().ToArray();
        foreach (var (device, history) in withActivity)
        {
            foreach (var entry in history.Entries.OrderBy(x => x.TimestampUtc))
            {
                var caveat = AnalystNoteContent.IsOlderThanOsInstall(ctx, entry.TimestampUtc)
                    ? AnalystNoteContent.PreInstallCaveat
                    : "";
                row = AddDataRow(sheet, row,
                [
                    device.ModelText,
                    DateDisplay.FormatMoscow(entry.TimestampUtc),
                    entry.KindText,
                    entry.PathText,
                    caveat
                ], highlight: caveat.Length > 0 ? CaveatColor : null);
            }
        }

        if (withActivity.Length == 0)
        {
            sheet.Cell(row++, 1).Value = "Следов работы с файлами на устройствах не найдено.";
        }

        var transfers = ctx.Transfers().ToArray();
        if (transfers.Length > 0)
        {
            row++;
            AddSectionHeader(sheet, row++, widths.Length, "Признаки переноса файлов");
            sheet.Range(row, 1, row, widths.Length).Merge();
            sheet.Cell(row, 1).Value = Clean(ctx.TransferVerdict());
            sheet.Cell(row, 1).Style.Alignment.WrapText = true;
            sheet.Row(row).Height = 30;
        }
    }

    // ------------------------------------------------------------------
    // Лист «Хронология»: раздел 4 — одна лента всех событий.
    // ------------------------------------------------------------------
    private static void AddChronologySheet(XLWorkbook workbook, ForensicReportContext ctx)
    {
        var sheet = workbook.Worksheets.Add("Хронология");
        ConfigureSheet(sheet);
        sheet.Column(1).Width = 24;
        sheet.Column(2).Width = 110;
        sheet.Column(3).Width = 52;

        AddTitle(sheet, "4. Полная хронология",
            "Одна лента: устройства, сеть, файлы и очистка в порядке времени. "
            + "Помеченные даты старше установки ОС: штамп из артефакта хранит время файла-источника, а не момент действия.", 3);

        var row = 4;
        row = AddTableHeader(sheet, row, ["Когда", "Событие", "Примечание"]);

        foreach (var entry in AnalystNoteContent.BuildChronology(ctx))
        {
            row = AddDataRow(sheet, row,
            [
                DateDisplay.FormatMoscow(entry.At),
                entry.Text,
                entry.IsOlderThanOsInstall ? AnalystNoteContent.PreInstallCaveat : ""
            ], highlight: entry.IsOlderThanOsInstall ? CaveatColor : null);
        }
    }

    // ------------------------------------------------------------------
    // Местные помощники оформления.
    // ------------------------------------------------------------------
    private static void ConfigureSheet(IXLWorksheet sheet)
    {
        sheet.Style.Font.FontName = "Calibri";
        sheet.Style.Font.FontSize = 10;
        sheet.SheetView.FreezeRows(4);
    }

    private static void AddTitle(IXLWorksheet sheet, string title, string subtitle, int columns)
    {
        sheet.Range(1, 1, 1, columns).Merge();
        sheet.Cell(1, 1).Value = Clean(title);
        sheet.Cell(1, 1).Style.Font.Bold = true;
        sheet.Cell(1, 1).Style.Font.FontSize = 14;
        sheet.Row(1).Height = 24;

        sheet.Range(2, 1, 2, columns).Merge();
        sheet.Cell(2, 1).Value = Clean(subtitle);
        sheet.Cell(2, 1).Style.Font.FontColor = XLColor.FromHtml("#4A6076");
        sheet.Cell(2, 1).Style.Alignment.WrapText = true;
        sheet.Row(2).Height = 30;
    }

    private static void AddSectionHeader(IXLWorksheet sheet, int row, int columns, string title)
    {
        sheet.Range(row, 1, row, columns).Merge();
        sheet.Cell(row, 1).Value = Clean(title);
        sheet.Cell(row, 1).Style.Font.Bold = true;
        sheet.Cell(row, 1).Style.Fill.BackgroundColor = SectionColor;
        sheet.Row(row).Height = 20;
    }

    private static void AddKeyValueRow(IXLWorksheet sheet, int row, string label, string? value, bool tall = false)
    {
        sheet.Cell(row, 1).Value = Clean(label);
        sheet.Cell(row, 1).Style.Font.Bold = true;
        sheet.Cell(row, 1).Style.Alignment.Vertical = XLAlignmentVerticalValues.Top;
        sheet.Cell(row, 2).Value = Clean(value);
        sheet.Cell(row, 2).Style.Alignment.WrapText = true;
        sheet.Cell(row, 2).Style.Alignment.Vertical = XLAlignmentVerticalValues.Top;
        var range = sheet.Range(row, 1, row, 2);
        range.Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
        range.Style.Border.OutsideBorderColor = BorderColor;
        if (tall)
        {
            sheet.Row(row).Height = 44;
        }
    }

    private static int AddTableHeader(IXLWorksheet sheet, int row, IReadOnlyList<string> headers)
    {
        for (var i = 0; i < headers.Count; i++)
        {
            var cell = sheet.Cell(row, i + 1);
            cell.Value = headers[i];
            cell.Style.Font.Bold = true;
            cell.Style.Font.FontColor = XLColor.White;
            cell.Style.Fill.BackgroundColor = HeaderColor;
        }

        sheet.Row(row).Height = 20;
        return row + 1;
    }

    private static int AddDataRow(IXLWorksheet sheet, int row, IReadOnlyList<string> cells, XLColor? highlight = null)
    {
        for (var i = 0; i < cells.Count; i++)
        {
            var cell = sheet.Cell(row, i + 1);
            cell.Value = Clean(cells[i]);
            cell.Style.Alignment.WrapText = true;
            cell.Style.Alignment.Vertical = XLAlignmentVerticalValues.Top;
            cell.Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
            cell.Style.Border.OutsideBorderColor = BorderColor;
            if (highlight is not null)
            {
                cell.Style.Fill.BackgroundColor = highlight;
            }
        }

        return row + 1;
    }

    private static string Clean(string? value)
    {
        var normalized = ReportText.ForPdf(value, 32000);
        return string.IsNullOrWhiteSpace(normalized) ? "" : normalized;
    }
}
