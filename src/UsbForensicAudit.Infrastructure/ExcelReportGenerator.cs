using ClosedXML.Excel;

namespace UsbForensicAudit;

internal static class ExcelReportGenerator
{
    private static readonly XLColor TitleColor = XLColor.FromHtml("#0D2136");
    private static readonly XLColor HeaderColor = XLColor.FromHtml("#1F4E78");
    private static readonly XLColor SectionColor = XLColor.FromHtml("#D9EAF7");
    private static readonly XLColor BorderColor = XLColor.FromHtml("#AFC4D4");
    private static readonly XLColor RealUsbColor = XLColor.FromHtml("#DDF3E8");
    private static readonly XLColor StorageColor = XLColor.FromHtml("#FFF1C9");
    private static readonly XLColor UsbFlagsColor = XLColor.FromHtml("#E9E3FA");
    private static readonly XLColor SupportColor = XLColor.FromHtml("#E8EEF5");
    private static readonly XLColor DangerColor = XLColor.FromHtml("#FDE2E6");

    public static void GenerateFull(string path, ForensicReportContext context)
    {
        using var workbook = CreateWorkbook(
            "Полный отчёт UsbForensicAudit",
            "Полные результаты forensic-аудита USB-устройств");

        AddSummarySheet(workbook, context, isBrief: false);
        AddDevicesSheet(workbook, context.ReportableDevices, "USB устройства");
        AddEvidenceSheet(workbook, context.Timeline);
        AddCleanupSheet(workbook, context.CleanupFindings, brief: false);
        AddWarningsSheet(workbook, context.Result.SourceWarnings);
        AddExternalUtilitiesSheet(workbook, context.ExternalUtilitySnapshot);

        workbook.SaveAs(path);
    }

    public static void GenerateBrief(string path, ForensicReportContext context)
    {
        using var workbook = CreateWorkbook(
            "Сводный отчёт UsbForensicAudit",
            "Краткие результаты forensic-аудита USB-устройств");

        AddSummarySheet(workbook, context, isBrief: true);
        AddCleanupSheet(workbook, context.SuspiciousFindings.Take(20), brief: true);

        var notableDevices = context.RealDevices
            .OrderByDescending(x => x.LastSeenUtc ?? x.FirstConnectedUtc ?? DateTimeOffset.MinValue)
            .Take(25);
        AddDevicesSheet(workbook, notableDevices, "Значимые USB");
        AddWarningsSheet(workbook, context.Result.SourceWarnings);

        workbook.SaveAs(path);
    }

    private static XLWorkbook CreateWorkbook(string title, string subject)
    {
        var workbook = new XLWorkbook();
        workbook.Properties.Title = title;
        workbook.Properties.Subject = subject;
        workbook.Properties.Author = "UsbForensicAudit";
        workbook.Properties.Company = "UsbForensicAudit";
        workbook.Properties.Comments = "Все даты представлены в московском времени (МСК).";
        return workbook;
    }

    private static void AddSummarySheet(XLWorkbook workbook, ForensicReportContext context, bool isBrief)
    {
        var result = context.Result;
        var worksheet = workbook.Worksheets.Add("Сводка");
        ConfigureSheet(worksheet);
        worksheet.Column(1).Width = 28;
        worksheet.Column(2).Width = 44;
        worksheet.Column(3).Width = 4;
        worksheet.Column(4).Width = 30;
        worksheet.Column(5).Width = 18;
        worksheet.Column(6).Width = 18;

        AddTitle(
            worksheet,
            isBrief ? "Сводный отчёт по проверке USB" : "Полный отчёт по forensic-аудиту USB",
            $"Компьютер: {result.ComputerName} | Сформировано: {DateDisplay.FormatMoscow(DateTimeOffset.UtcNow)}",
            6);

        var row = 4;
        AddSectionHeader(worksheet, row++, 1, 2, "Общие сведения");
        foreach (var (label, value) in new[]
                 {
                     ("Компьютер", result.ComputerName),
                     ("Пользователь", result.UserName),
                     ("Windows", result.WindowsVersion),
                     ("Установка Windows", result.OsInstalledAtText),
                     ("Начало сканирования", DateDisplay.FormatMoscow(result.StartedAtUtc)),
                     ("Окончание сканирования", DateDisplay.FormatMoscow(result.FinishedAtUtc)),
                     ("Длительность", context.ScanDurationText),
                     ("Права администратора", result.IsAdministrator ? "да" : "нет"),
                     ("Область отчёта", "Только USB/Type-C, включая встроенные устройства внутренней USB-шины"),
                     ("Исключено", "ОЗУ и внутренние SATA/NVMe-накопители — они не относятся к USB")
                 })
        {
            AddKeyValueRow(worksheet, row++, 1, label, value);
        }

        worksheet.Cell(row, 1).Value = "Примечание";
        worksheet.Cell(row, 1).Style.Font.Bold = true;
        worksheet.Cell(row, 2).Value = Normalize(result.OsInstallGraceNote);
        worksheet.Cell(row, 2).Style.Alignment.WrapText = true;

        var metricRow = 4;
        AddSectionHeader(worksheet, metricRow++, 4, 6, "Ключевые показатели");
        foreach (var (label, value) in new[]
                 {
                     ("USB/Type-C записей", context.ReportableDevices.Count),
                     ("Реальных USB-устройств", context.RealDevices.Count),
                     ("USB-доказательств", context.Timeline.Count),
                     ("Релевантных признаков очистки", context.CleanupFindings.Count),
                     ("Подозрительных", context.SuspiciousCount),
                     ("Высокий риск", context.HighRiskCount),
                     ("Предупреждений", result.SourceWarnings.Count)
                 })
        {
            worksheet.Cell(metricRow, 4).Value = label;
            worksheet.Range(metricRow, 5, metricRow, 6).Merge();
            worksheet.Cell(metricRow, 5).Value = value;
            worksheet.Cell(metricRow, 5).Style.Font.Bold = true;
            worksheet.Cell(metricRow, 5).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
            ApplyThinBorder(worksheet.Range(metricRow, 4, metricRow, 6));
            metricRow++;
        }

        metricRow++;
        AddSectionHeader(worksheet, metricRow++, 4, 6, "Оценка");
        var risk = ResolveRisk(context);
        worksheet.Range(metricRow, 4, metricRow, 6).Merge();
        worksheet.Cell(metricRow, 4).Value = risk.Text;
        worksheet.Cell(metricRow, 4).Style.Font.Bold = true;
        worksheet.Cell(metricRow, 4).Style.Font.FontColor = risk.FontColor;
        worksheet.Cell(metricRow, 4).Style.Fill.BackgroundColor = risk.BackgroundColor;
        worksheet.Cell(metricRow, 4).Style.Alignment.WrapText = true;
        worksheet.Row(metricRow).Height = 38;

        var tableRow = Math.Max(row + 3, metricRow + 3);
        AddSectionHeader(worksheet, tableRow++, 1, 3, "Устройства по категориям");
        WriteSmallTable(
            worksheet,
            tableRow,
            1,
            ["Категория", "Количество"],
            context.DevicesByCategory.Select(x => new[] { x.Category, x.Count.ToString() }));

        AddSectionHeader(worksheet, tableRow - 1, 4, 6, "Доказательства по источникам");
        WriteSmallTable(
            worksheet,
            tableRow,
            4,
            ["Источник", "Количество"],
            context.EvidenceBySource.Select(x => new[] { x.Source, x.Count.ToString() }));

        worksheet.SheetView.FreezeRows(2);
        worksheet.TabColor = HeaderColor;
    }

    private static void AddDevicesSheet(
        XLWorkbook workbook,
        IEnumerable<UsbDeviceRecord> devices,
        string sheetName)
    {
        var rows = devices.ToArray();
        var columns = new[]
        {
            Column<UsbDeviceRecord>("Категория", 24, x => x.CategoryText),
            Column<UsbDeviceRecord>("Имя устройства", 36, x => x.DisplayName),
            Column<UsbDeviceRecord>("Описание записи", 46, x => x.UserMeaning),
            Column<UsbDeviceRecord>("Когда подключали", 24, x => x.FirstConnectedText),
            Column<UsbDeviceRecord>("Последняя активность", 24, x => x.LastSeenText),
            Column<UsbDeviceRecord>("Когда отключали", 30, x => x.LastDisconnectedText),
            Column<UsbDeviceRecord>("Производитель", 24, x => x.ManufacturerText),
            Column<UsbDeviceRecord>("Модель", 30, x => x.ModelText),
            Column<UsbDeviceRecord>("VID / PID", 18, x => x.VidPidText),
            Column<UsbDeviceRecord>("Серийный номер", 24, x => x.SerialText),
            Column<UsbDeviceRecord>("Расположение", 30, x => x.LocationDisplayText),
            Column<UsbDeviceRecord>("Источник", 34, x => x.SourceText),
            Column<UsbDeviceRecord>("Пояснение по датам", 48, x => x.DateConfidenceText),
            Column<UsbDeviceRecord>("Буквы/тома", 36, x => string.Join("; ", new[] { x.DriveLetters, x.VolumeHints }.Where(v => v.Length > 0))),
            Column<UsbDeviceRecord>("Системный ID / путь", 54, x => x.DeviceInstanceId),
            Column<UsbDeviceRecord>("Canonical device", 30, x => x.CanonicalDeviceId + (x.IsCanonicalPrimary ? " (primary)" : "")),
            Column<UsbDeviceRecord>("Связанные source IDs", 60, x => string.Join("; ", x.LinkedSourceIds))
        };

        var worksheet = AddDataSheet(workbook, sheetName, "История USB-устройств и связанных forensic-записей", rows, columns);
        for (var index = 0; index < rows.Length; index++)
        {
            var color = rows[index].VisualCategory switch
            {
                "RealUsb" => RealUsbColor,
                "RelatedStorage" => StorageColor,
                "UsbFlagsTrace" => UsbFlagsColor,
                _ => SupportColor
            };
            worksheet.Range(index + 5, 1, index + 5, columns.Length).Style.Fill.BackgroundColor = color;
        }
    }

    private static void AddEvidenceSheet(XLWorkbook workbook, IEnumerable<EvidenceRecord> evidence)
    {
        var rows = evidence.OrderByDescending(x => x.TimestampUtc).ToArray();
        AddDataSheet(
            workbook,
            "Доказательства",
            "Системные события и пользовательские артефакты, использованные при анализе",
            rows,
            [
                Column<EvidenceRecord>("Дата и время", 24, x => x.TimestampText),
                Column<EvidenceRecord>("Категория", 26, x => x.EvidenceCategory),
                Column<EvidenceRecord>("Источник", 32, x => x.SourceText),
                Column<EvidenceRecord>("Событие", 15, x => x.EventId),
                Column<EvidenceRecord>("Уровень", 15, x => x.Level),
                Column<EvidenceRecord>("Связанное устройство", 42, x => x.DeviceHint),
                Column<EvidenceRecord>("Пояснение", 52, x => x.UserExplanationText),
                Column<EvidenceRecord>("Подробности", 62, x => x.Summary)
            ]);
    }

    private static void AddCleanupSheet(
        XLWorkbook workbook,
        IEnumerable<CleanupFinding> findings,
        bool brief)
    {
        var rows = findings
            .OrderByDescending(x => x.IsSuspicious)
            .ThenByDescending(x => SeverityRank(x.Severity))
            .ThenByDescending(x => x.TimestampUtc)
            .ToArray();

        var worksheet = AddDataSheet(
            workbook,
            brief ? "Инциденты" : "Следы очистки",
            brief
                ? "Ключевые подозрительные события (не более 20)"
                : "Все найденные признаки очистки, включая нормальные события после установки Windows",
            rows,
            [
                Column<CleanupFinding>("Дата и время", 24, x => x.TimestampText),
                Column<CleanupFinding>("Статус", 24, x => x.AssessmentText),
                Column<CleanupFinding>("Риск", 16, x => x.SeverityText),
                Column<CleanupFinding>("Действие", 24, x => x.ActionKindText),
                Column<CleanupFinding>("Уверенность", 20, x => x.ConfidenceText),
                Column<CleanupFinding>("Инициатор", 30, x => x.InitiatorText),
                Column<CleanupFinding>("Инструмент", 26, x => x.PossibleToolText),
                Column<CleanupFinding>("Область", 28, x => x.AreaText),
                Column<CleanupFinding>("Что найдено", 44, x => x.Finding),
                Column<CleanupFinding>("Подробности", 62, x => x.Details)
            ]);

        for (var index = 0; index < rows.Length; index++)
        {
            if (rows[index].IsSuspicious)
            {
                worksheet.Range(index + 5, 1, index + 5, 10).Style.Fill.BackgroundColor = DangerColor;
            }
        }
    }

    private static void AddWarningsSheet(XLWorkbook workbook, IEnumerable<string> warnings)
    {
        var rows = warnings.Select((text, index) => new WarningRow(index + 1, text)).ToArray();
        AddDataSheet(
            workbook,
            "Предупреждения",
            "Источники, которые были недоступны или обработаны с ограничениями",
            rows,
            [
                Column<WarningRow>("№", 8, x => x.Number.ToString()),
                Column<WarningRow>("Предупреждение", 100, x => x.Text)
            ]);
    }

    private static void AddExternalUtilitiesSheet(
        XLWorkbook workbook,
        ExternalUtilityReportSnapshot? snapshot)
    {
        if (snapshot is null)
        {
            return;
        }

        var worksheet = AddDataSheet(
            workbook,
            "Сторонние утилиты",
            $"Снимок {snapshot.UtilityName ?? "USB-утилиты"}: {DateDisplay.FormatMoscow(snapshot.CapturedAtUtc)}",
            snapshot.Rows,
            [
                Column<ExternalUtilityRow>("Раздел", 28, x => x.SectionTitle),
                Column<ExternalUtilityRow>("Утилита", 22, x => x.UtilityName),
                Column<ExternalUtilityRow>("Запись", 38, x => x.PrimaryText),
                Column<ExternalUtilityRow>("VID / PID", 18, x => x.VidPidText),
                Column<ExternalUtilityRow>("Производитель / модель", 34, x => x.VendorProductText),
                Column<ExternalUtilityRow>("Вердикт", 42, x => x.VerdictDisplayText),
                Column<ExternalUtilityRow>("Ключевые поля", 54, x => x.KeyFieldsText),
                Column<ExternalUtilityRow>("Анализ", 62, x => x.AnalysisText),
                Column<ExternalUtilityRow>("Все поля", 70, x => x.FormattedDetailsText)
            ]);

        if (snapshot.HistoricalLaunches.Count == 0)
        {
            return;
        }

        var startRow = snapshot.Rows.Count + 8;
        AddSectionHeader(worksheet, startRow++, 1, 5, "История запусков сторонних утилит");
        WriteSmallTable(
            worksheet,
            startRow,
            1,
            ["Дата", "Утилита", "Источник", "Описание"],
            snapshot.HistoricalLaunches
                .OrderByDescending(x => x.TimestampUtc)
                .Select(x => new[] { x.TimestampText, x.ToolName, x.Source, x.Summary }));
    }

    private static IXLWorksheet AddDataSheet<T>(
        XLWorkbook workbook,
        string sheetName,
        string description,
        IReadOnlyList<T> rows,
        IReadOnlyList<ExcelColumn<T>> columns)
    {
        var worksheet = workbook.Worksheets.Add(sheetName);
        ConfigureSheet(worksheet);
        AddTitle(worksheet, sheetName, description, columns.Count);

        const int headerRow = 4;
        for (var columnIndex = 0; columnIndex < columns.Count; columnIndex++)
        {
            var columnNumber = columnIndex + 1;
            worksheet.Cell(headerRow, columnNumber).Value = columns[columnIndex].Header;
            worksheet.Column(columnNumber).Width = columns[columnIndex].Width;
        }

        var header = worksheet.Range(headerRow, 1, headerRow, columns.Count);
        header.Style.Fill.BackgroundColor = HeaderColor;
        header.Style.Font.FontColor = XLColor.White;
        header.Style.Font.Bold = true;
        header.Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
        header.Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
        header.Style.Alignment.WrapText = true;
        worksheet.Row(headerRow).Height = 32;

        for (var rowIndex = 0; rowIndex < rows.Count; rowIndex++)
        {
            var excelRow = headerRow + rowIndex + 1;
            for (var columnIndex = 0; columnIndex < columns.Count; columnIndex++)
            {
                worksheet.Cell(excelRow, columnIndex + 1).Value =
                    Normalize(columns[columnIndex].Value(rows[rowIndex]));
            }
        }

        var lastRow = Math.Max(headerRow + 1, headerRow + rows.Count);
        var dataRange = worksheet.Range(headerRow + 1, 1, lastRow, columns.Count);
        dataRange.Style.Alignment.Vertical = XLAlignmentVerticalValues.Top;
        dataRange.Style.Alignment.WrapText = true;
        dataRange.Style.Font.FontSize = 9;
        ApplyThinBorder(worksheet.Range(headerRow, 1, lastRow, columns.Count));

        if (rows.Count == 0)
        {
            worksheet.Range(headerRow + 1, 1, headerRow + 1, columns.Count).Merge();
            worksheet.Cell(headerRow + 1, 1).Value = "Записей нет";
            worksheet.Cell(headerRow + 1, 1).Style.Font.Italic = true;
            worksheet.Cell(headerRow + 1, 1).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
        }
        else
        {
            worksheet.Range(headerRow, 1, headerRow + rows.Count, columns.Count).SetAutoFilter();
        }

        worksheet.SheetView.FreezeRows(headerRow);
        worksheet.SheetView.FreezeColumns(1);
        worksheet.TabColor = HeaderColor;
        return worksheet;
    }

    private static void ConfigureSheet(IXLWorksheet worksheet)
    {
        worksheet.Style.Font.FontName = "Segoe UI";
        worksheet.Style.Font.FontSize = 10;
        worksheet.Style.Alignment.Vertical = XLAlignmentVerticalValues.Top;
        worksheet.ShowGridLines = false;
    }

    private static void AddTitle(
        IXLWorksheet worksheet,
        string title,
        string subtitle,
        int columnCount)
    {
        worksheet.Range(1, 1, 1, columnCount).Merge();
        worksheet.Cell(1, 1).Value = title;
        worksheet.Cell(1, 1).Style.Fill.BackgroundColor = TitleColor;
        worksheet.Cell(1, 1).Style.Font.FontColor = XLColor.White;
        worksheet.Cell(1, 1).Style.Font.Bold = true;
        worksheet.Cell(1, 1).Style.Font.FontSize = 16;
        worksheet.Cell(1, 1).Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
        worksheet.Row(1).Height = 30;

        worksheet.Range(2, 1, 2, columnCount).Merge();
        worksheet.Cell(2, 1).Value = Normalize(subtitle);
        worksheet.Cell(2, 1).Style.Font.FontColor = XLColor.FromHtml("#4B6475");
        worksheet.Cell(2, 1).Style.Font.Italic = true;
        worksheet.Cell(2, 1).Style.Alignment.WrapText = true;
        worksheet.Row(2).Height = 26;
    }

    private static void AddSectionHeader(
        IXLWorksheet worksheet,
        int row,
        int firstColumn,
        int lastColumn,
        string text)
    {
        worksheet.Range(row, firstColumn, row, lastColumn).Merge();
        var cell = worksheet.Cell(row, firstColumn);
        cell.Value = text;
        cell.Style.Fill.BackgroundColor = SectionColor;
        cell.Style.Font.Bold = true;
        cell.Style.Font.FontColor = TitleColor;
        cell.Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
        worksheet.Row(row).Height = 23;
    }

    private static void AddKeyValueRow(
        IXLWorksheet worksheet,
        int row,
        int firstColumn,
        string label,
        string value)
    {
        worksheet.Cell(row, firstColumn).Value = label;
        worksheet.Cell(row, firstColumn).Style.Font.Bold = true;
        worksheet.Cell(row, firstColumn + 1).Value = Normalize(value);
        worksheet.Cell(row, firstColumn + 1).Style.Alignment.WrapText = true;
        ApplyThinBorder(worksheet.Range(row, firstColumn, row, firstColumn + 1));
    }

    private static void WriteSmallTable(
        IXLWorksheet worksheet,
        int startRow,
        int startColumn,
        IReadOnlyList<string> headers,
        IEnumerable<string[]> rows)
    {
        for (var index = 0; index < headers.Count; index++)
        {
            worksheet.Cell(startRow, startColumn + index).Value = headers[index];
        }

        var header = worksheet.Range(startRow, startColumn, startRow, startColumn + headers.Count - 1);
        header.Style.Fill.BackgroundColor = HeaderColor;
        header.Style.Font.FontColor = XLColor.White;
        header.Style.Font.Bold = true;

        var rowNumber = startRow + 1;
        foreach (var values in rows)
        {
            for (var index = 0; index < headers.Count; index++)
            {
                worksheet.Cell(rowNumber, startColumn + index).Value =
                    Normalize(index < values.Length ? values[index] : "");
            }
            rowNumber++;
        }

        ApplyThinBorder(worksheet.Range(
            startRow,
            startColumn,
            Math.Max(startRow + 1, rowNumber - 1),
            startColumn + headers.Count - 1));
    }

    private static void ApplyThinBorder(IXLRange range)
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

    private static ExcelColumn<T> Column<T>(string header, double width, Func<T, string> value) =>
        new(header, width, value);

    private static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "—";
        }

        var normalized = ReportText.ForPdf(value, 32000);
        return string.IsNullOrWhiteSpace(normalized) ? "—" : normalized;
    }

    private static int SeverityRank(string severity) =>
        severity.ToLowerInvariant() switch
        {
            "critical" => 5,
            "high" => 4,
            "medium" => 3,
            "low" => 2,
            "info" => 1,
            _ => 0
        };

    private static RiskStyle ResolveRisk(ForensicReportContext context)
    {
        if (context.HighRiskCount > 0)
        {
            return new RiskStyle(
                "Высокий риск: обнаружены признаки высокого уровня. Требуется ручная проверка доказательств и обстоятельств.",
                XLColor.FromHtml("#8B1E2D"),
                DangerColor);
        }

        if (context.SuspiciousCount > 0)
        {
            return new RiskStyle(
                "Повышенное внимание: обнаружены подозрительные признаки. Они не являются доказательством очистки без дополнительной проверки.",
                XLColor.FromHtml("#7A5200"),
                StorageColor);
        }

        return new RiskStyle(
            "Явных подозрительных признаков очистки не обнаружено. Отсутствие артефактов само по себе не доказывает отсутствие активности.",
            XLColor.FromHtml("#17633A"),
            RealUsbColor);
    }

    private sealed record ExcelColumn<T>(string Header, double Width, Func<T, string> Value);

    private sealed record WarningRow(int Number, string Text);

    private sealed record RiskStyle(string Text, XLColor FontColor, XLColor BackgroundColor);
}
