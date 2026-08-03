using System.IO;
using ClosedXML.Excel;
using static UsbForensicAudit.ExcelStyleHelper;

namespace UsbForensicAudit;

internal static class ExcelReportGenerator
{
    private static readonly XLColor TitleColor = XLColor.FromHtml("#0D2136");
    private static readonly XLColor RealUsbColor = XLColor.FromHtml("#DDF3E8");
    private static readonly XLColor StorageColor = XLColor.FromHtml("#FFF1C9");
    private static readonly XLColor UsbFlagsColor = XLColor.FromHtml("#E9E3FA");
    private static readonly XLColor SupportColor = XLColor.FromHtml("#E8EEF5");
    private static readonly XLColor ExternalPeripheralColor = XLColor.FromHtml("#D6ECFB");
    private static readonly XLColor DangerColor = XLColor.FromHtml("#FDE2E6");
    private static readonly XLColor AlternatingRowColor = XLColor.FromHtml("#F5F8FB");
    private static readonly XLColor WhiteColor = XLColor.White;

    public static void GenerateFull(string path, ForensicReportContext context)
    {
        using var output = File.Create(path);
        GenerateFull(output, context);
    }

    /// <summary>Пишет отчёт в поток: тесты проверяют содержимое без записи на диск.</summary>
    public static void GenerateFull(Stream output, ForensicReportContext context)
    {
        using var workbook = CreateWorkbook(
            "Полный отчёт UsbForensicAudit",
            "Полные результаты forensic-аудита USB-устройств");

        AddSummarySheet(workbook, context, isBrief: false);
        AddDevicesSheet(workbook, context.ReportableDevices, "USB устройства");
        AddDeviceActivitySheet(workbook, context);
        AddFileTransferSheet(workbook, context);
        AddEvidenceSheet(workbook, context.Timeline);
        AddNetworkSheet(workbook, context);
        AddNetworkEnvironmentSheet(workbook, context);
        AddNetworkVisitsSheet(workbook, context);
        AddNetworkSessionsSheet(workbook, context);
        AddCleanupSheet(workbook, context.CleanupFindings, brief: false);
        AddWarningsSheet(workbook, context.Result.SourceWarnings);
        AddExternalUtilitiesSheet(workbook, context.ExternalUtilitySnapshot);

        workbook.SaveAs(output);
    }

    public static void GenerateBrief(string path, ForensicReportContext context)
    {
        using var output = File.Create(path);
        GenerateBrief(output, context);
    }

    /// <summary>Пишет отчёт в поток: тесты проверяют содержимое без записи на диск.</summary>
    public static void GenerateBrief(Stream output, ForensicReportContext context)
    {
        using var workbook = CreateWorkbook(
            "Сводный отчёт UsbForensicAudit",
            "Краткие результаты forensic-аудита USB-устройств");

        AddSummarySheet(workbook, context, isBrief: true);
        AddCleanupSheet(workbook, context.SuspiciousFindings.Take(20), brief: true);

        AddDevicesSheet(workbook, context.ReportableDevices, "Все USB устройства");
        AddWarningsSheet(workbook, context.Result.SourceWarnings);

        workbook.SaveAs(output);
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
        worksheet.Column(3).Width = 12;
        worksheet.Column(4).Width = 28;
        worksheet.Column(5).Width = 42;
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
        worksheet.Row(row).Height = EstimateRowHeight(
            [("Примечание", worksheet.Column(1).Width), (Normalize(result.OsInstallGraceNote), worksheet.Column(2).Width)],
            minimum: 28,
            maximum: 72);

        var metricRow = 4;
        AddSectionHeader(worksheet, metricRow++, 4, 6, "Ключевые показатели");
        foreach (var (label, value) in new (string Label, string Value)[]
                 {
                     ("Физических устройств", context.Counts.PhysicalDevices.ToString()),
                     ("Записей в источниках", context.Counts.RegistryRecords.ToString()),
                     ("Сведено к уже перечисленным", context.Counts.MergedRecords.ToString()),
                     ("USB-доказательств", context.Timeline.Count.ToString()),
                     ("Релевантных признаков очистки", context.CleanupFindings.Count.ToString()),
                     ("Подозрительных", context.SuspiciousCount.ToString()),
                     ("Требуют внимания", context.AttentionCount.ToString()),
                     ("Устройств со следами работы с файлами",
                         context.DevicesWithActivity().Count().ToString()),
                     ("Признаков переноса файлов", context.Transfers().Count().ToString()),
                     ("Сетевых связей", context.NetworkSummary.Connections.ToString()),
                     ("Связей, по которым данные могли уйти",
                         context.NetworkSummary.OutsideReach.ToString()),
                     ("Обращений по сети", context.NetworkSummary.Visits.ToString()),
                     ("Высокий риск", context.HighRiskCount.ToString()),
                     ("Предупреждений", result.SourceWarnings.Count.ToString()),
                     ("Canonical с точной датой",
                         $"{result.Coverage.CanonicalDevicesWithExactDates}/{result.Coverage.CanonicalDeviceCount} ({result.Coverage.ExactDateCoveragePercent:0.##}%)")
                 })
        {
            worksheet.Cell(metricRow, 4).Value = label;
            worksheet.Range(metricRow, 5, metricRow, 6).Merge();
            worksheet.Cell(metricRow, 5).Value = value;
            worksheet.Cell(metricRow, 5).Style.Font.Bold = true;
            worksheet.Cell(metricRow, 5).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
            worksheet.Range(metricRow, 4, metricRow, 6).Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
            worksheet.Range(metricRow, 4, metricRow, 6).Style.Alignment.WrapText = true;
            ApplyThinBorder(worksheet.Range(metricRow, 4, metricRow, 6));
            worksheet.Row(metricRow).Height = 24;
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
        worksheet.Row(metricRow).Height = EstimateRowHeight(
            [(risk.Text, worksheet.Column(4).Width + worksheet.Column(5).Width + worksheet.Column(6).Width)],
            minimum: 42,
            maximum: 72);

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

        var coverageRow = tableRow
                          + Math.Max(context.DevicesByCategory.Count, context.EvidenceBySource.Count)
                          + 3;
        AddSectionHeader(worksheet, coverageRow++, 1, 6, "Покрытие источников");
        WriteSmallTable(
            worksheet,
            coverageRow,
            1,
            ["Источник", "Статус", "Записей", "Лимит", "Ошибка / ограничение"],
            result.Coverage.Sources.Select(source => new[]
            {
                source.Source,
                source.Status,
                source.Count.ToString(),
                source.Capped
                    ? source.Limit > 0 ? source.Limit.ToString() : "достигнут"
                    : "нет",
                source.Error
            }));

        worksheet.SheetView.FreezeRows(2);
        worksheet.SheetView.ZoomScale = 90;
        ConfigurePrintLayout(worksheet, 1, 6, 1, 2);
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
            Column<UsbDeviceRecord>("Приносили ли с собой", 30, x => x.ExternalityText),
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
            // Лист содержит все записи реестра, а список в программе — устройства.
            // Без этой колонки числа в отчёте и на экране не сходятся.
            Column<UsbDeviceRecord>("Место в списке устройств", 34, x => DeviceComposition.IsFoldedByDefault(x)
                ? "свёрнута в своё устройство"
                : "отдельная строка"),
            Column<UsbDeviceRecord>("Связанные source IDs", 60, x => string.Join("; ", x.LinkedSourceIds)),
            Column<UsbDeviceRecord>("Transport", 28, x => x.Transport),
            Column<UsbDeviceRecord>("Connection", 28, x => x.Connection),
            Column<UsbDeviceRecord>("Classification", 22, x => x.Classification),
            Column<UsbDeviceRecord>("Confidence / provenance", 58, x =>
                $"{x.TransportConfidence}/{x.ConnectionConfidence}/{x.ClassificationConfidence}: {x.ClassificationEvidenceText}")
        };

        var worksheet = AddDataSheet(workbook, sheetName, "История USB-устройств и связанных forensic-записей", rows, columns);
        for (var index = 0; index < rows.Length; index++)
        {
            // Цвет отвечает на тот же вопрос, что и во вкладке программы:
            // приносили устройство с собой или оно всегда было внутри машины.
            var color = rows[index].Externality switch
            {
                DeviceExternality.ExternalMedia => RealUsbColor,
                DeviceExternality.ExternalPeripheral => ExternalPeripheralColor,
                DeviceExternality.PossiblyExternal => StorageColor,
                DeviceExternality.VirtualDevice => UsbFlagsColor,
                DeviceExternality.RegistryTrace => UsbFlagsColor,
                _ => SupportColor
            };
            worksheet.Range(index + 5, 1, index + 5, columns.Length).Style.Fill.BackgroundColor = color;
        }
    }

    /// <summary>
    /// Что делали на каждом устройстве, одним листом. Столбец с основанием
    /// привязки обязателен: без него строка «открывали E:\Фото» не проверяется,
    /// а буква диска за год могла достаться нескольким носителям.
    /// </summary>
    private static void AddDeviceActivitySheet(XLWorkbook workbook, ForensicReportContext context)
    {
        var rows = context.DevicesWithActivity()
            .SelectMany(x => x.History.Entries.Select(entry => (Device: x.Device, Entry: entry)))
            .OrderBy(x => x.Device.DisplayName, StringComparer.CurrentCulture)
            .ThenByDescending(x => x.Entry.TimestampUtc)
            .ToArray();

        AddDataSheet(
            workbook,
            "Действия на устройствах",
            "Какие папки открывали, какие файлы открывали и удаляли, что запускали — по каждому устройству. "
            + "Столбец «Почему отнесено к устройству» показывает основание привязки.",
            rows,
            [
                Column<(UsbDeviceRecord Device, DeviceActivityEntry Entry)>("Устройство", 34, x => x.Device.DisplayName),
                Column<(UsbDeviceRecord Device, DeviceActivityEntry Entry)>("Когда", 24, x => x.Entry.TimestampText),
                Column<(UsbDeviceRecord Device, DeviceActivityEntry Entry)>("Что делали", 34, x => x.Entry.KindText),
                Column<(UsbDeviceRecord Device, DeviceActivityEntry Entry)>("Папка или файл", 60, x => x.Entry.PathText),
                Column<(UsbDeviceRecord Device, DeviceActivityEntry Entry)>("Кто", 28, x => x.Entry.UserText),
                Column<(UsbDeviceRecord Device, DeviceActivityEntry Entry)>("Почему отнесено к устройству", 46, x => x.Entry.LinkText),
                Column<(UsbDeviceRecord Device, DeviceActivityEntry Entry)>("Что означает время", 52, x => x.Entry.TimeMeaning),
                Column<(UsbDeviceRecord Device, DeviceActivityEntry Entry)>("Откуда взято", 32, x => x.Entry.SourceText),
                Column<(UsbDeviceRecord Device, DeviceActivityEntry Entry)>("Ссылка на источник", 64, x => x.Entry.Provenance)
            ]);
    }

    /// <summary>
    /// Перенос файлов отдельным листом: это единственное место в отчёте, где
    /// сказано, какие именно файлы переходили между устройством и машиной.
    /// Столбцы с надёжностью и основанием обязательны — подтверждённое журналом
    /// файловой системы и совпадение имён имеют разный вес.
    /// </summary>
    private static void AddFileTransferSheet(XLWorkbook workbook, ForensicReportContext context)
    {
        var rows = context.Transfers()
            .OrderByDescending(x => x.Indication.Confidence != "Low")
            .ThenByDescending(x => x.Indication.SeenLocallyUtc)
            .ToArray();

        AddDataSheet(
            workbook,
            "Перенос файлов",
            context.TransferVerdict(),
            rows,
            [
                Column<(UsbDeviceRecord Device, CopyIndication Indication)>("Устройство", 34, x => x.Device.DisplayName),
                Column<(UsbDeviceRecord Device, CopyIndication Indication)>("Имя файла", 40, x => x.Indication.FileName),
                Column<(UsbDeviceRecord Device, CopyIndication Indication)>("Куда перенесли", 30, x => x.Indication.DirectionText),
                Column<(UsbDeviceRecord Device, CopyIndication Indication)>("Насколько надёжен вывод", 24, x => x.Indication.ConfidenceText),
                Column<(UsbDeviceRecord Device, CopyIndication Indication)>("Разрыв во времени", 18, x => x.Indication.GapText),
                Column<(UsbDeviceRecord Device, CopyIndication Indication)>("Путь на устройстве", 56, x => x.Indication.PathOnDevice),
                Column<(UsbDeviceRecord Device, CopyIndication Indication)>("Когда виден на устройстве", 24, x => x.Indication.SeenOnDeviceText),
                Column<(UsbDeviceRecord Device, CopyIndication Indication)>("Путь на внутреннем диске", 56, x => x.Indication.LocalPath),
                Column<(UsbDeviceRecord Device, CopyIndication Indication)>("Когда виден на диске", 24, x => x.Indication.SeenLocallyText),
                Column<(UsbDeviceRecord Device, CopyIndication Indication)>("На чём основан вывод", 70, x => x.Indication.Basis),
                Column<(UsbDeviceRecord Device, CopyIndication Indication)>("Откуда взято", 34, x => x.Indication.Source)
            ]);
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
                Column<EvidenceRecord>("Сила доказательства", 22, x => x.EvidenceStrength),
                Column<EvidenceRecord>("Уверенность", 18, x => x.Confidence),
                Column<EvidenceRecord>("Событие", 15, x => x.EventId),
                Column<EvidenceRecord>("Уровень", 15, x => x.Level),
                Column<EvidenceRecord>("Связанное устройство", 42, x => x.DeviceHint),
                Column<EvidenceRecord>("Пояснение", 52, x => x.UserExplanationText),
                Column<EvidenceRecord>("Подробности", 62, x => x.Summary),
                Column<EvidenceRecord>("Provenance", 70, x => x.Provenance)
            ]);
    }

    /// <summary>
    /// Связи машины с внешним миром одним листом. Строки, по которым данные
    /// могли уйти, выделены тем же цветом, что и подозрительные находки: читатель
    /// листа не должен искать сетевую папку среди сотни посещённых сайтов.
    /// </summary>
    private static void AddNetworkSheet(XLWorkbook workbook, ForensicReportContext context)
    {
        var rows = context.NetworkConnections;
        var worksheet = AddDataSheet(
            workbook,
            "Сетевые подключения",
            context.NetworkSummary.Describe(),
            rows,
            [
                Column<NetworkConnectionRecord>("Как связывались", 26, x => x.KindText),
                Column<NetworkConnectionRecord>("С чем именно", 44, x => x.TargetText),
                Column<NetworkConnectionRecord>("Кто начал", 26, x => x.DirectionText),
                Column<NetworkConnectionRecord>("Что нашлось внутри", 28, x => x.ActivityText),
                Column<NetworkConnectionRecord>("Первое подключение", 24, x => x.FirstSeenText),
                Column<NetworkConnectionRecord>("Откуда первая дата", 40, x => x.FirstSeenProvenance),
                Column<NetworkConnectionRecord>("Последнее подключение", 24, x => x.LastSeenText),
                Column<NetworkConnectionRecord>("Откуда последняя дата", 40, x => x.LastSeenProvenance),
                Column<NetworkConnectionRecord>("Чем защищено", 34, x => x.SecurityText),
                Column<NetworkConnectionRecord>("Через что шла связь", 34, x => x.AdapterText),
                Column<NetworkConnectionRecord>("Адреса этой машины", 48, x => x.LocalAddressesText),
                Column<NetworkConnectionRecord>("Учётная запись", 26, x => x.AccountText),
                Column<NetworkConnectionRecord>("Простыми словами", 70, x => x.DetailsText),
                Column<NetworkConnectionRecord>("Откуда взято", 40, x => x.SourcesText)
            ]);

        for (var index = 0; index < rows.Count; index++)
        {
            if (rows[index].IsOutsideReach)
            {
                worksheet.Range(index + 5, 1, index + 5, 14).Style.Fill.BackgroundColor = DangerColor;
            }
        }
    }

    private static void AddNetworkEnvironmentSheet(XLWorkbook workbook, ForensicReportContext context)
    {
        var env = context.NetworkEnvironment;
        AddDataSheet(
            workbook,
            "Wi-Fi в эфире",
            env.Describe(),
            env.WirelessNetworks,
            [
                Column<WirelessNetworkRecord>("SSID", 34, x => x.SsidText),
                Column<WirelessNetworkRecord>("Связь с машиной", 40, x => x.RelationText),
                Column<WirelessNetworkRecord>("Сигнал", 12, x => x.SignalText),
                Column<WirelessNetworkRecord>("Канал", 18, x => x.ChannelText),
                Column<WirelessNetworkRecord>("Защита", 50, x => x.SecurityText),
                Column<WirelessNetworkRecord>("BSSID", 20, x => x.BssidText),
                Column<WirelessNetworkRecord>("Производитель AP", 24, x => x.VendorText),
                Column<WirelessNetworkRecord>("Адаптер", 34, x => x.Adapter),
                Column<WirelessNetworkRecord>("Когда слышали", 24, x => x.SeenAtText)
            ]);

        AddDataSheet(
            workbook,
            "Устройства в сети",
            env.Describe(),
            env.Neighbors,
            [
                Column<NetworkNeighborRecord>("Роль", 34, x => x.RoleText),
                Column<NetworkNeighborRecord>("IP", 18, x => x.AddressText),
                Column<NetworkNeighborRecord>("MAC", 20, x => x.MacText),
                Column<NetworkNeighborRecord>("Имя", 34, x => x.NameText),
                Column<NetworkNeighborRecord>("Производитель", 24, x => x.VendorText),
                Column<NetworkNeighborRecord>("Как найдено", 44, x => x.DiscoveryText),
                Column<NetworkNeighborRecord>("Состояние", 18, x => x.StateText),
                Column<NetworkNeighborRecord>("Сеть", 24, x => x.NetworkText),
                Column<NetworkNeighborRecord>("Адаптер", 28, x => x.AdapterText),
                Column<NetworkNeighborRecord>("Когда видели", 24, x => x.SeenAtText)
            ]);
    }

    /// <summary>
    /// Куда ходили по каждой связи: папки на серверах, введённые пути, адреса
    /// страниц. Лист отвечает на вопрос «что именно смотрели», на который список
    /// связей ответить не может.
    /// </summary>
    private static void AddNetworkVisitsSheet(XLWorkbook workbook, ForensicReportContext context)
    {
        var rows = context.NetworkConnections
            .SelectMany(connection => connection.Visits.Select(visit => (Connection: connection, Visit: visit)))
            .OrderBy(x => NetworkConnectionKind.Rank(x.Connection.Kind))
            .ThenBy(x => x.Connection.Name, StringComparer.CurrentCulture)
            .ThenByDescending(x => x.Visit.WhenUtc)
            .ToArray();

        AddDataSheet(
            workbook,
            "Куда ходили по сети",
            "Папки на серверах, подключённые диски, введённые вручную пути и адреса страниц. "
            + "Столбец «Что означает время» показывает, о каком именно моменте говорит отметка.",
            rows,
            [
                Column<(NetworkConnectionRecord Connection, NetworkVisit Visit)>("Связь", 34, x => x.Connection.TargetText),
                Column<(NetworkConnectionRecord Connection, NetworkVisit Visit)>("Как связывались", 24, x => x.Connection.KindText),
                Column<(NetworkConnectionRecord Connection, NetworkVisit Visit)>("Когда", 24, x => x.Visit.WhenText),
                Column<(NetworkConnectionRecord Connection, NetworkVisit Visit)>("Что делали", 34, x => x.Visit.KindText),
                Column<(NetworkConnectionRecord Connection, NetworkVisit Visit)>("Папка, адрес или узел", 70, x => x.Visit.TargetText),
                Column<(NetworkConnectionRecord Connection, NetworkVisit Visit)>("Подпись", 44, x => x.Visit.TitleText),
                Column<(NetworkConnectionRecord Connection, NetworkVisit Visit)>("Кто", 28, x => x.Visit.UserText),
                Column<(NetworkConnectionRecord Connection, NetworkVisit Visit)>("Сколько раз", 30, x => x.Visit.CountText),
                Column<(NetworkConnectionRecord Connection, NetworkVisit Visit)>("Что означает время", 52, x => x.Visit.TimeMeaning),
                Column<(NetworkConnectionRecord Connection, NetworkVisit Visit)>("Откуда взято", 34, x => x.Visit.SourceText),
                Column<(NetworkConnectionRecord Connection, NetworkVisit Visit)>("Ссылка на источник", 64, x => x.Visit.Provenance)
            ]);
    }

    /// <summary>
    /// Когда именно связь была установлена и разорвана. Отдельные события,
    /// сеансом не являющиеся, помечены прямо в столбце отключения.
    /// </summary>
    private static void AddNetworkSessionsSheet(XLWorkbook workbook, ForensicReportContext context)
    {
        var rows = context.NetworkConnections
            .SelectMany(connection => connection.Sessions.Select(session => (Connection: connection, Session: session)))
            .OrderByDescending(x => x.Session.StartedUtc)
            .ToArray();

        AddDataSheet(
            workbook,
            "Сеансы связи",
            "Пары «подключение — отключение» из журналов Windows. Отдельные события, у которых "
            + "конца нет и быть не может, помечены в столбце «Отключение».",
            rows,
            [
                Column<(NetworkConnectionRecord Connection, NetworkSession Session)>("Связь", 34, x => x.Connection.TargetText),
                Column<(NetworkConnectionRecord Connection, NetworkSession Session)>("Как связывались", 24, x => x.Connection.KindText),
                Column<(NetworkConnectionRecord Connection, NetworkSession Session)>("Подключение", 24, x => x.Session.StartedText),
                Column<(NetworkConnectionRecord Connection, NetworkSession Session)>("Отключение", 34, x => x.Session.EndedText),
                Column<(NetworkConnectionRecord Connection, NetworkSession Session)>("Сколько держалось", 20, x => x.Session.DurationText),
                Column<(NetworkConnectionRecord Connection, NetworkSession Session)>("Чем закончилось", 48, x => x.Session.OutcomeText),
                Column<(NetworkConnectionRecord Connection, NetworkSession Session)>("Подробности", 62, x => x.Session.ReasonText),
                Column<(NetworkConnectionRecord Connection, NetworkSession Session)>("Учётная запись", 26, x => x.Session.Account),
                Column<(NetworkConnectionRecord Connection, NetworkSession Session)>("Откуда взято", 34, x => x.Session.SourceText),
                Column<(NetworkConnectionRecord Connection, NetworkSession Session)>("Ссылка на источник", 64, x => x.Session.Provenance)
            ]);
    }

    private static void AddCleanupSheet(
        XLWorkbook workbook,
        IEnumerable<CleanupFinding> findings,
        bool brief)
    {
        var rows = findings
            .OrderByDescending(x => x.IsSuspicious)
            .ThenByDescending(x => ReportSeverity.Rank(x.Severity))
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
                Column<CleanupFinding>("Подробности", 62, x => x.DetailsWithNote)
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
        header.Style.Font.FontSize = 10;
        header.Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
        header.Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
        header.Style.Alignment.WrapText = true;
        worksheet.Row(headerRow).Height = 36;

        for (var rowIndex = 0; rowIndex < rows.Count; rowIndex++)
        {
            var excelRow = headerRow + rowIndex + 1;
            var heightInputs = new List<(string Value, double Width)>(columns.Count);
            for (var columnIndex = 0; columnIndex < columns.Count; columnIndex++)
            {
                var value = Normalize(columns[columnIndex].Value(rows[rowIndex]));
                var cell = worksheet.Cell(excelRow, columnIndex + 1);
                cell.Value = value;
                cell.Style.Alignment.Horizontal = AlignmentFor(columns[columnIndex].Header);
                heightInputs.Add((value, columns[columnIndex].Width));
            }

            worksheet.Row(excelRow).Height = EstimateRowHeight(
                heightInputs,
                MinimumDataRowHeight,
                MaximumDataRowHeight);
        }

        var lastRow = Math.Max(headerRow + 1, headerRow + rows.Count);
        var dataRange = worksheet.Range(headerRow + 1, 1, lastRow, columns.Count);
        dataRange.Style.Alignment.Vertical = XLAlignmentVerticalValues.Top;
        dataRange.Style.Alignment.WrapText = true;
        dataRange.Style.Font.FontSize = 9;
        ApplyAlternatingRows(worksheet, headerRow + 1, lastRow, columns.Count);
        ApplyThinBorder(worksheet.Range(headerRow, 1, lastRow, columns.Count));

        if (rows.Count == 0)
        {
            worksheet.Range(headerRow + 1, 1, headerRow + 1, columns.Count).Merge();
            worksheet.Cell(headerRow + 1, 1).Value = "Записей нет";
            worksheet.Cell(headerRow + 1, 1).Style.Font.Italic = true;
            worksheet.Cell(headerRow + 1, 1).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
            worksheet.Cell(headerRow + 1, 1).Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
            worksheet.Row(headerRow + 1).Height = 28;
        }
        else
        {
            worksheet.Range(headerRow, 1, headerRow + rows.Count, columns.Count).SetAutoFilter();
        }

        worksheet.SheetView.Freeze(headerRow, 1);
        worksheet.SheetView.ZoomScale = columns.Count >= 15 ? 70 : columns.Count >= 9 ? 80 : 90;
        ConfigurePrintLayout(worksheet, 1, columns.Count, 1, headerRow);
        worksheet.TabColor = HeaderColor;
        return worksheet;
    }

    private static void ConfigureSheet(IXLWorksheet worksheet)
    {
        worksheet.Style.Font.FontName = "Segoe UI";
        worksheet.Style.Font.FontSize = 10;
        worksheet.Style.Alignment.Vertical = XLAlignmentVerticalValues.Top;
        worksheet.Style.Alignment.WrapText = false;
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
        worksheet.Cell(1, 1).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Left;
        worksheet.Cell(1, 1).Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
        worksheet.Row(1).Height = 34;

        worksheet.Range(2, 1, 2, columnCount).Merge();
        worksheet.Cell(2, 1).Value = Normalize(subtitle);
        worksheet.Cell(2, 1).Style.Font.FontColor = XLColor.FromHtml("#4B6475");
        worksheet.Cell(2, 1).Style.Font.Italic = true;
        worksheet.Cell(2, 1).Style.Alignment.WrapText = true;
        worksheet.Cell(2, 1).Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
        worksheet.Row(2).Height = 30;
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
        cell.Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Left;
        cell.Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
        worksheet.Row(row).Height = 25;
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
        worksheet.Range(row, firstColumn, row, firstColumn + 1).Style.Alignment.Vertical =
            XLAlignmentVerticalValues.Center;
        worksheet.Row(row).Height = EstimateRowHeight(
            [(label, worksheet.Column(firstColumn).Width), (Normalize(value), worksheet.Column(firstColumn + 1).Width)],
            minimum: 22,
            maximum: 66);
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
        header.Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
        header.Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
        header.Style.Alignment.WrapText = true;
        worksheet.Row(startRow).Height = 28;

        var rowNumber = startRow + 1;
        foreach (var values in rows)
        {
            var heightInputs = new List<(string Value, double Width)>(headers.Count);
            for (var index = 0; index < headers.Count; index++)
            {
                var value = Normalize(index < values.Length ? values[index] : "");
                var cell = worksheet.Cell(rowNumber, startColumn + index);
                cell.Value = value;
                cell.Style.Alignment.WrapText = true;
                cell.Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
                cell.Style.Alignment.Horizontal = AlignmentFor(headers[index]);
                heightInputs.Add((value, worksheet.Column(startColumn + index).Width));
            }
            worksheet.Row(rowNumber).Height = EstimateRowHeight(heightInputs, 21, 72);
            rowNumber++;
        }

        var tableRange = worksheet.Range(
            startRow,
            startColumn,
            Math.Max(startRow + 1, rowNumber - 1),
            startColumn + headers.Count - 1);
        ApplyThinBorder(tableRange);
        ApplyAlternatingRows(
            worksheet,
            startRow + 1,
            Math.Max(startRow + 1, rowNumber - 1),
            startColumn + headers.Count - 1,
            startColumn);
    }

    private static void ApplyAlternatingRows(
        IXLWorksheet worksheet,
        int firstRow,
        int lastRow,
        int lastColumn,
        int firstColumn = 1)
    {
        if (lastRow < firstRow)
        {
            return;
        }

        for (var row = firstRow; row <= lastRow; row++)
        {
            worksheet.Range(row, firstColumn, row, lastColumn).Style.Fill.BackgroundColor =
                (row - firstRow) % 2 == 0 ? WhiteColor : AlternatingRowColor;
        }
    }

    private static XLAlignmentHorizontalValues AlignmentFor(string header)
    {
        if (header.Contains("Дата", StringComparison.OrdinalIgnoreCase)
            || header.Contains("Когда", StringComparison.OrdinalIgnoreCase)
            || header.Contains("Статус", StringComparison.OrdinalIgnoreCase)
            || header.Contains("Риск", StringComparison.OrdinalIgnoreCase)
            || header.Contains("Уверенность", StringComparison.OrdinalIgnoreCase)
            || header.Contains("Сила", StringComparison.OrdinalIgnoreCase)
            || header.Contains("Количество", StringComparison.OrdinalIgnoreCase)
            || header.Contains("Записей", StringComparison.OrdinalIgnoreCase)
            || header is "№" or "Событие" or "Уровень" or "VID / PID" or "Transport" or "Connection")
        {
            return XLAlignmentHorizontalValues.Center;
        }

        return XLAlignmentHorizontalValues.Left;
    }

    private static void ConfigurePrintLayout(
        IXLWorksheet worksheet,
        int firstColumn,
        int lastColumn,
        int firstRepeatRow,
        int lastRepeatRow)
    {
        worksheet.PageSetup.PageOrientation = XLPageOrientation.Landscape;
        worksheet.PageSetup.PaperSize = XLPaperSize.A4Paper;
        worksheet.PageSetup.PagesWide = lastColumn - firstColumn + 1 >= 15 ? 2 : 1;
        worksheet.PageSetup.PagesTall = 0;
        worksheet.PageSetup.CenterHorizontally = true;
        worksheet.PageSetup.ShowGridlines = false;
        worksheet.PageSetup.SetRowsToRepeatAtTop(firstRepeatRow, lastRepeatRow);
        worksheet.PageSetup.Margins.Top = 0.45;
        worksheet.PageSetup.Margins.Bottom = 0.45;
        worksheet.PageSetup.Margins.Left = 0.3;
        worksheet.PageSetup.Margins.Right = 0.3;
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
                "Повышенное внимание: обнаружены подозрительные признаки. Они не являются доказательством очистки без дополнительной проверки. "
                + context.CleanupVerdict(),
                XLColor.FromHtml("#7A5200"),
                StorageColor);
        }

        // Зелёный вердикт «ничего не найдено» рядом с запуском USBDeview и
        // лежащим на диске USB Oblivion читается как разрешение не проверять.
        if (context.AttentionCount > 0)
        {
            return new RiskStyle(
                context.CleanupVerdict(),
                XLColor.FromHtml("#7A5200"),
                StorageColor);
        }

        return new RiskStyle(
            context.CleanupVerdict(),
            XLColor.FromHtml("#17633A"),
            RealUsbColor);
    }

    private sealed record ExcelColumn<T>(string Header, double Width, Func<T, string> Value);

    private sealed record WarningRow(int Number, string Text);

    private sealed record RiskStyle(string Text, XLColor FontColor, XLColor BackgroundColor);
}
