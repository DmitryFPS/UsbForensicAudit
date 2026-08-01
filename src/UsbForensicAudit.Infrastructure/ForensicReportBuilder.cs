using System.Net;
using System.Text;

namespace UsbForensicAudit;

internal sealed class ForensicReportContext
{
    public ForensicReportContext(AuditResult result, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null)
    {
        Result = result;
        ExternalUtilitySnapshot = externalUtilitySnapshot;
        ReportableDevices = BuildUsbScopeDevices(result.Devices);
        ListedDevices = ReportableDevices
            .Where(x => !DeviceComposition.IsFoldedByDefault(x))
            .ToArray();
        RealDevices = ReportableDevices
            .Where(x => x.VisualCategory.Equals("RealUsb", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Timeline = result.Evidence
            .Where(x => IsUsbScopeEvidence(x, ReportableDevices))
            .OrderByDescending(x => x.TimestampUtc)
            .ToArray();
        CleanupFindings = result.CleanupFindings
            .Where(IsUsbScopeCleanupFinding)
            .OrderByDescending(x => x.TimestampUtc)
            .ToArray();
        SuspiciousFindings = CleanupFindings
            .Where(x => x.IsSuspicious)
            .OrderByDescending(x => SeverityRank(x.Severity))
            .ThenByDescending(x => x.TimestampUtc)
            .ToArray();
        HighRiskFindings = SuspiciousFindings
            .Where(x => x.Severity.Equals("High", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        AttentionFindings = CleanupFindings
            .Where(x => x.NeedsAttention)
            .OrderByDescending(x => SeverityRank(x.Severity))
            .ThenByDescending(x => x.TimestampUtc)
            .ToArray();
        EvidenceBySource = Timeline
            .GroupBy(x => x.SourceText)
            .OrderByDescending(g => g.Count())
            .Select(g => (Source: g.Key, Count: g.Count()))
            .ToArray();
        DevicesByCategory = ReportableDevices
            .GroupBy(x => x.CategoryText)
            .OrderByDescending(g => g.Count())
            .Select(g => (Category: g.Key, Count: g.Count()))
            .ToArray();
        Counts = DeviceCountSummary.FromDevices(ReportableDevices);
        NetworkConnections = result.NetworkConnections
            .OrderBy(x => NetworkConnectionKind.Rank(x.Kind))
            .ThenByDescending(x => x.LastSeenUtc ?? DateTimeOffset.MinValue)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        NetworkSummary = NetworkConnectionSummary.Create(NetworkConnections);
        NetworkEnvironment = result.NetworkEnvironment;
    }

    public AuditResult Result { get; }
    public ExternalUtilityReportSnapshot? ExternalUtilitySnapshot { get; }
    public IReadOnlyList<CleanupFinding> CleanupFindings { get; }
    public IReadOnlyList<CleanupFinding> SuspiciousFindings { get; }
    public IReadOnlyList<CleanupFinding> HighRiskFindings { get; }

    /// <summary>
    /// Находки, которые не являются доказательством очистки, но которые читатель
    /// сводки обязан увидеть: запуск утилит работы с USB и наличие средств
    /// удаления следов.
    /// </summary>
    public IReadOnlyList<CleanupFinding> AttentionFindings { get; }
    public IReadOnlyList<EvidenceRecord> Timeline { get; }
    public IReadOnlyList<UsbDeviceRecord> ReportableDevices { get; }

    /// <summary>
    /// Устройства так, как их видит читатель во вкладке: одна вещь — одна
    /// строка. Записи, которые Windows завела на части того же устройства,
    /// перечислены внутри его досье. Полная таблица отчёта по-прежнему содержит
    /// все записи: досье пишется о вещах, таблица доказывает полноту разбора.
    /// </summary>
    public IReadOnlyList<UsbDeviceRecord> ListedDevices { get; }

    public IReadOnlyList<UsbDeviceRecord> RealDevices { get; }
    public IReadOnlyList<(string Source, int Count)> EvidenceBySource { get; }
    public IReadOnlyList<(string Category, int Count)> DevicesByCategory { get; }

    /// <summary>
    /// Единственный источник чисел об устройствах для всех отчётов.
    /// </summary>
    public DeviceCountSummary Counts { get; }

    /// <summary>
    /// Связи машины с внешним миром в том же порядке, в каком они стоят во
    /// вкладке: сверху то, чем данные могли уйти.
    /// </summary>
    public IReadOnlyList<NetworkConnectionRecord> NetworkConnections { get; }

    /// <summary>Единственный источник чисел о сетевых связях для всех отчётов.</summary>
    public NetworkConnectionSummary NetworkSummary { get; }

    /// <summary>Снимок Wi-Fi в эфире и соседей по сети на момент съёмки.</summary>
    public NetworkEnvironmentSnapshot NetworkEnvironment { get; }

    public int SuspiciousCount => SuspiciousFindings.Count;
    public int HighRiskCount => HighRiskFindings.Count;
    public int AttentionCount => AttentionFindings.Count;

    /// <summary>
    /// Одна и та же оценка очистки для всех отчётов. Формулировка «ничего не
    /// обнаружено» допустима, только когда не найдено вообще ничего: ни
    /// подозрительных признаков, ни запусков утилит, ни средств удаления следов.
    /// </summary>
    public string CleanupVerdict()
    {
        if (SuspiciousCount > 0)
        {
            return $"Подозрительных признаков очистки: {SuspiciousCount}"
                   + (HighRiskCount > 0 ? $", из них высокого риска: {HighRiskCount}." : ".")
                   + (AttentionCount > 0
                       ? $" Дополнительно требуют внимания: {AttentionCount}."
                       : "");
        }

        if (AttentionCount == 0)
        {
            return "Признаков очистки или сокрытия следов не обнаружено. "
                   + "Отсутствие артефактов само по себе не доказывает отсутствие активности.";
        }

        return $"Подозрительных признаков очистки не обнаружено, но есть находки, "
               + $"требующие внимания ({AttentionCount}): "
               + string.Join("; ", AttentionFindings.Take(5).Select(DescribeAttention))
               + ". Запуск такой программы и её наличие на диске сами по себе не доказывают "
               + "удаление следов, но и не позволяют считать, что следов никто не касался.";
    }

    private static string DescribeAttention(CleanupFinding finding) =>
        finding.ActionKind.Equals("ToolPresence", StringComparison.OrdinalIgnoreCase)
            ? $"на машине найдена программа {finding.PossibleToolText}, запуск не подтверждён"
            : $"{finding.TimestampText} — запуск программы {finding.PossibleToolText} "
              + $"({finding.InitiatorText})";

    public string ScanDurationText
    {
        get
        {
            var duration = Result.FinishedAtUtc - Result.StartedAtUtc;
            return duration.TotalSeconds < 1
                ? "менее 1 сек."
                : $"{(int)duration.TotalMinutes} мин. {duration.Seconds} сек.";
        }
    }

    public static ForensicReportContext Create(AuditResult result, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null) =>
        new(result, externalUtilitySnapshot);

    private readonly Dictionary<string, DeviceActivityHistory> _activityCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Что делали на устройстве: какие папки открывали, какие файлы открывали и
    /// удаляли, что запускали. Разбор одного устройства проходит по всему списку
    /// улик, поэтому результат запоминается: досье и сводные листы просят одно и
    /// то же по нескольку раз.
    /// </summary>
    public DeviceActivityHistory GetActivity(UsbDeviceRecord device)
    {
        var key = device.DeviceInstanceId.Length > 0 ? device.DeviceInstanceId : device.CanonicalDeviceId;
        if (_activityCache.TryGetValue(key, out var cached))
        {
            return cached;
        }

        var history = DeviceActivityBuilder.Build(device, Result);
        _activityCache[key] = history;
        return history;
    }

    /// <summary>
    /// Устройства, по которым вообще есть что рассказать о работе с файлами.
    /// </summary>
    public IEnumerable<(UsbDeviceRecord Device, DeviceActivityHistory History)> DevicesWithActivity() =>
        ListedDevices
            .Select(device => (Device: device, History: GetActivity(device)))
            .Where(x => !x.History.IsEmpty);

    /// <summary>
    /// Одна фраза о работе с файлами для всех отчётов. Отдельно называет число
    /// устройств, по которым искать было не по чему: без этого нулевой результат
    /// прочитают как «на устройствах ничего не делали».
    /// </summary>
    public string ActivityVerdict()
    {
        var withActivity = DevicesWithActivity().ToArray();
        var searchable = ListedDevices.Count(x => GetActivity(x).CanSearchFileActivity);
        var actions = withActivity.Sum(x => x.History.Entries.Count);
        var unsearchable = ListedDevices.Count - searchable;
        var tail = unsearchable > 0
            ? $" Ещё у {unsearchable} устройств нет буквы диска, серийного номера тома или видимого имени, "
              + "поэтому следы работы с файлами по ним искать нечем."
            : "";

        return withActivity.Length == 0
            ? $"Следов работы с файлами не найдено ни по одному из {searchable} устройств, "
              + "по которым поиск был возможен." + tail
            : $"Восстановлена работа с файлами по {withActivity.Length} устройствам из {searchable}, "
              + $"по которым поиск был возможен: всего {actions} действий." + tail;
    }

    /// <summary>
    /// Признаки переноса файлов, отобранные по всем устройствам сразу.
    /// </summary>
    public IEnumerable<(UsbDeviceRecord Device, CopyIndication Indication)> Transfers() =>
        DevicesWithActivity()
            .SelectMany(x => x.History.CopyIndications.Select(indication => (x.Device, Indication: indication)));

    /// <summary>
    /// Одна фраза о переносе файлов для всех отчётов.
    ///
    /// Главное здесь — разделить подтверждённое журналом файловой системы и
    /// догадку по совпадению имён, и назвать период, за который журнал вообще
    /// сохранился. Без периода вывод «переносов не найдено» читается как «файлы
    /// не переносили», хотя журнал мог просто не дожить до нужной даты.
    /// </summary>
    public string TransferVerdict()
    {
        var transfers = Transfers().ToArray();
        var confirmed = transfers.Count(x => x.Indication.Confidence != "Low");
        var coverage = Result.FileChangeJournals.Count == 0
            ? " Журнал изменений NTFS не читался, поэтому перенос файлов подтвердить нечем: "
              + "проверка опиралась только на совпадение имён."
            : " " + string.Join(" ", Result.FileChangeJournals.Select(x => x.CoverageText));

        if (transfers.Length == 0)
        {
            return "Признаков переноса файлов между устройствами и этой машиной не найдено." + coverage;
        }

        var devices = transfers.Select(x => x.Device.CanonicalDeviceId).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        return $"Признаков переноса файлов: {transfers.Length} по {devices} устройствам. "
               + (confirmed > 0
                   ? $"Из них {confirmed} подтверждены журналом изменений NTFS."
                   : "Все они основаны только на совпадении имён файлов.")
               + coverage;
    }

    public static IEnumerable<EvidenceRecord> GetRelatedEvidence(ForensicReportContext context, UsbDeviceRecord device)
    {
        var tokens = BuildSearchTokens(device).ToArray();
        if (tokens.Length == 0)
        {
            yield break;
        }

        foreach (var evidence in context.Timeline
                     .Where(x => !x.Source.Equals("Correlation", StringComparison.OrdinalIgnoreCase))
                     .OrderByDescending(x => x.TimestampUtc))
        {
            if (tokens.Any(token => ContainsToken(evidence, token)))
            {
                yield return evidence;
            }
        }
    }

    public static IEnumerable<EvidenceRecord> GetCorrelationEvidence(ForensicReportContext context, UsbDeviceRecord device)
    {
        return context.Timeline
            .Where(x => x.Source.Equals("Correlation", StringComparison.OrdinalIgnoreCase)
                        && ContainsIgnoreCase(x.DeviceHint, device.DeviceInstanceId))
            .OrderByDescending(x => x.TimestampUtc);
    }

    private static UsbDeviceRecord[] BuildUsbScopeDevices(IReadOnlyList<UsbDeviceRecord> devices)
    {
        var coreUsb = devices
            .Where(DeviceTransportClassifier.IsReportable)
            .ToArray();

        return devices
            .Where(x =>
                coreUsb.Contains(x)
                || x.VisualCategory.Equals("UsbFlagsTrace", StringComparison.OrdinalIgnoreCase)
                || (x.VisualCategory.Equals("RelatedStorage", StringComparison.OrdinalIgnoreCase)
                    && coreUsb.Any(usb => IsRelatedStorage(x, usb))))
            .Distinct()
            .OrderBy(x => x.CanonicalDeviceId)
            .ThenByDescending(x => x.IsCanonicalPrimary)
            .ToArray();
    }

    private static bool IsRelatedStorage(UsbDeviceRecord storage, UsbDeviceRecord usb)
    {
        if (!string.IsNullOrWhiteSpace(storage.CanonicalDeviceId)
            && storage.CanonicalDeviceId.Equals(usb.CanonicalDeviceId, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(storage.ContainerId)
            && storage.ContainerId.Equals(usb.ContainerId, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (DeviceIdentityGraph.IsHardwareSerial(storage.Serial)
            && DeviceIdentityGraph.IsHardwareSerial(usb.Serial)
            && DeviceIdentityGraph.NormalizeSerial(storage.Serial)
                .Equals(DeviceIdentityGraph.NormalizeSerial(usb.Serial), StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(storage.ParentIdPrefix)
               && (usb.Serial.Contains(storage.ParentIdPrefix, StringComparison.OrdinalIgnoreCase)
                   || usb.ParentIdPrefix.Contains(storage.ParentIdPrefix, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsUsbScopeEvidence(EvidenceRecord evidence, IReadOnlyList<UsbDeviceRecord> devices)
    {
        if (evidence.EventId is "104" or "1102")
        {
            return true;
        }

        if (evidence.Source.Contains("setupapi", StringComparison.OrdinalIgnoreCase)
            || evidence.Source.Contains("Журнал контроля USB", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var text = string.Join(
            " ",
            evidence.Source,
            evidence.EvidenceCategory,
            evidence.DeviceHint,
            evidence.Summary,
            evidence.RawText,
            evidence.UserExplanation);
        if (ContainsUsbMarker(text))
        {
            return true;
        }

        return devices.Any(device => BuildSearchTokens(device).Any(token => ContainsToken(evidence, token)));
    }

    private static bool IsUsbScopeCleanupFinding(CleanupFinding finding)
    {
        if (finding.ActionKind.Equals("LogClearing", StringComparison.OrdinalIgnoreCase)
            || finding.Area.Equals("SetupAPI", StringComparison.OrdinalIgnoreCase)
            || finding.Assessment.Equals("OsInstall", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (finding.IsUsbUtilityTool)
        {
            return true;
        }

        return ContainsUsbMarker(string.Join(
            " ",
            finding.Area,
            finding.Finding,
            finding.Details,
            finding.PossibleTool));
    }

    private static bool ContainsUsbMarker(string value)
    {
        return value.Contains("USB", StringComparison.OrdinalIgnoreCase)
               || value.Contains("Type-C", StringComparison.OrdinalIgnoreCase)
               || value.Contains("USB-C", StringComparison.OrdinalIgnoreCase)
               || value.Contains("VID_", StringComparison.OrdinalIgnoreCase)
               || value.Contains("PID_", StringComparison.OrdinalIgnoreCase)
               || value.Contains("WPDBUSENUM", StringComparison.OrdinalIgnoreCase)
               || value.Contains("SCSI", StringComparison.OrdinalIgnoreCase)
               || value.Contains("STORAGE", StringComparison.OrdinalIgnoreCase)
               || DeviceMarkerText.ContainsWord(value, "WPD")
               || DeviceMarkerText.ContainsWord(value, "USB4")
               || value.Contains("THUNDERBOLT", StringComparison.OrdinalIgnoreCase)
               || value.Contains("removable", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeHardwareId(string value) =>
        value.Trim().Trim('{', '}').Replace("&0", "", StringComparison.OrdinalIgnoreCase);

    private static IEnumerable<string> BuildSearchTokens(UsbDeviceRecord device)
    {
        if (!string.IsNullOrWhiteSpace(device.DeviceInstanceId))
        {
            yield return device.DeviceInstanceId;
        }

        if (!string.IsNullOrWhiteSpace(device.Vid) && !string.IsNullOrWhiteSpace(device.Pid))
        {
            yield return $"VID_{device.Vid}&PID_{device.Pid}";
            yield return $"{device.Vid}:{device.Pid}";
        }

        if (!string.IsNullOrWhiteSpace(device.Serial) && device.Serial.Length >= 8)
        {
            yield return device.Serial;
        }

        if (!string.IsNullOrWhiteSpace(device.ContainerId))
        {
            yield return device.ContainerId;
        }

    }

    private static bool ContainsToken(EvidenceRecord evidence, string token)
    {
        return ContainsIgnoreCase(evidence.DeviceHint, token)
               || ContainsIgnoreCase(evidence.Summary, token)
               || ContainsIgnoreCase(evidence.RawText, token)
               || ContainsIgnoreCase(evidence.UserExplanation, token);
    }

    private static bool ContainsIgnoreCase(string? haystack, string needle)
    {
        return !string.IsNullOrWhiteSpace(haystack)
               && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private static int SeverityRank(string? severity) => severity?.ToUpperInvariant() switch
    {
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0
    };
}

internal static class ForensicReportBuilder
{
    public const string ReportTitle = "Аудит USB — полный отчёт для расследования";

    public static string BuildHtml(AuditResult result, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null)
    {
        var ctx = ForensicReportContext.Create(result, externalUtilitySnapshot);
        var html = new StringBuilder();
        html.AppendLine("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">");
        html.AppendLine($"<title>{E(ReportTitle)}</title>");
        html.AppendLine("""
            <style>
            :root{color-scheme:light}
            body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#111827;line-height:1.45;background:#fff}
            h1{font-size:28px;margin:0 0 8px}
            h2{font-size:20px;margin:28px 0 10px;padding-top:8px;border-top:2px solid #e5e7eb}
            h3{font-size:16px;margin:0 0 8px}
            p,li,td,th{font-size:12px}
            .meta,.note,.toc{background:#f8fafc;border:1px solid #dbeafe;border-radius:10px;padding:14px 16px;margin:12px 0}
            .warn{background:#fff7ed;border-color:#fdba74}
            .danger{background:#fef2f2;border-color:#fca5a5}
            table{border-collapse:collapse;width:100%;margin:12px 0}
            th,td{border:1px solid #d1d5db;padding:6px 7px;vertical-align:top;word-break:break-word}
            th{background:#eef2ff;position:sticky;top:0}
            tr:nth-child(even){background:#f9fafb}
            .high{color:#991b1b;font-weight:700}
            .medium{color:#92400e;font-weight:700}
            .low{color:#374151}
            .info{color:#1d4ed8;font-weight:700}
            .suspicious{background:#fff1f2}
            .card{border:1px solid #d1d5db;border-radius:10px;padding:14px 16px;margin:14px 0;background:#fff}
            .muted{color:#6b7280}
            .toc ul{margin:8px 0 0;padding-left:18px}
            @media print{body{margin:12px} th{position:static}}
            </style></head><body>
            """);

        html.AppendLine($"<h1>{E(ReportTitle)}</h1>");
        html.AppendLine("<div class=\"meta\">");
        html.AppendLine($"<b>Компьютер:</b> {E(result.ComputerName)}<br>");
        html.AppendLine($"<b>Пользователь:</b> {E(result.UserName)}<br>");
        html.AppendLine($"<b>Windows:</b> {E(result.WindowsVersion)}<br>");
        html.AppendLine($"<b>Установка Windows:</b> {E(result.OsInstalledAtText)}<br>");
        html.AppendLine($"<b>Начало сканирования:</b> {E(DateDisplay.FormatMoscow(result.StartedAtUtc))}<br>");
        html.AppendLine($"<b>Окончание сканирования:</b> {E(DateDisplay.FormatMoscow(result.FinishedAtUtc))}<br>");
        html.AppendLine($"<b>Длительность:</b> {E(ctx.ScanDurationText)}<br>");
        html.AppendLine($"<b>Права администратора:</b> {(result.IsAdministrator ? "да" : "нет")}<br>");
        html.AppendLine("<b>Область отчёта:</b> USB/Type-C, UASP, MTP/WPD и подтверждённые USB4/Thunderbolt tunnels; встроенные USB явно маркируются, внутренние SATA/NVMe без external topology evidence исключены.<br>");
        html.AppendLine($"<span class=\"muted\">{E(result.OsInstallGraceNote)}</span><br>");
        html.AppendLine($"<span class=\"muted\">{E(result.ReferenceImage.Describe())}</span>");
        html.AppendLine("</div>");

        html.AppendLine("<nav class=\"toc\"><b>Содержание</b><ul>");
        html.AppendLine("<li><a href=\"#summary\">1. Сводка для расследования</a></li>");
        html.AppendLine("<li><a href=\"#incidents\">2. Возможные инциденты</a></li>");
        html.AppendLine("<li><a href=\"#cleanup\">3. Все признаки очистки</a></li>");
        html.AppendLine("<li><a href=\"#devices\">4. USB-устройства</a></li>");
        html.AppendLine("<li><a href=\"#dossiers\">5. Досье устройств</a></li>");
        html.AppendLine("<li><a href=\"#timeline\">6. Хронология событий</a></li>");
        html.AppendLine("<li><a href=\"#evidence\">7. Журнал доказательств</a></li>");
        html.AppendLine("<li><a href=\"#network\">8. Сетевые подключения и куда по ним ходили</a></li>");
        html.AppendLine("<li><a href=\"#warnings\">9. Предупреждения и ограничения</a></li>");
        html.AppendLine("<li><a href=\"#methodology\">10. Источники данных</a></li>");
        if (ctx.ExternalUtilitySnapshot is not null && (ctx.ExternalUtilitySnapshot.Rows.Count > 0 || ctx.ExternalUtilitySnapshot.HistoricalLaunches.Count > 0))
        {
            html.AppendLine("<li><a href=\"#external-utils\">11. Сторонние утилиты</a></li>");
        }
        html.AppendLine("</ul></nav>");

        AppendSummarySection(html, ctx);
        AppendIncidentSection(html, ctx);
        AppendCleanupSection(html, ctx);
        AppendDevicesSection(html, ctx);
        AppendDossiersSection(html, ctx);
        AppendTimelineSection(html, ctx);
        AppendEvidenceSection(html, ctx);
        AppendNetworkSection(html, ctx);
        AppendNetworkEnvironmentSection(html, ctx);
        AppendWarningsSection(html, result);
        AppendMethodologySection(html);
        if (ctx.ExternalUtilitySnapshot is not null)
        {
            AppendExternalUtilitiesSection(html, ctx.ExternalUtilitySnapshot);
        }

        html.AppendLine("</body></html>");
        return html.ToString();
    }

    private static void AppendSummarySection(StringBuilder html, ForensicReportContext ctx)
    {
        var result = ctx.Result;
        html.AppendLine("<h2 id=\"summary\">1. Сводка для расследования</h2>");
        html.AppendLine("<div class=\"note\">");
        html.AppendLine($"<b>Физических устройств:</b> {ctx.Counts.PhysicalDevices}<br>");
        html.AppendLine($"<span class=\"muted\">{E(ctx.Counts.Describe())}</span><br>");
        html.AppendLine($"<b>USB-доказательств:</b> {ctx.Timeline.Count}; ");
        html.AppendLine($"<b>релевантных признаков очистки:</b> {ctx.CleanupFindings.Count}; ");
        html.AppendLine($"<b>подозрительных:</b> {ctx.SuspiciousCount}; ");
        html.AppendLine($"<b>требуют внимания:</b> {ctx.AttentionCount}; ");
        html.AppendLine($"<b>высокого риска:</b> {ctx.HighRiskCount}; ");
        html.AppendLine($"<b>предупреждений:</b> {result.SourceWarnings.Count}; ");
        html.AppendLine($"<b>canonical devices с точной датой:</b> {result.Coverage.CanonicalDevicesWithExactDates}/{result.Coverage.CanonicalDeviceCount} ({result.Coverage.ExactDateCoveragePercent:0.##}%)<br>");
        html.AppendLine($"<span class=\"muted\">{E(ctx.CleanupVerdict())}</span><br>");
        html.AppendLine($"<span class=\"muted\">{E(ctx.ActivityVerdict())}</span><br>");
        html.AppendLine($"<span class=\"muted\">{E(ctx.TransferVerdict())}</span><br>");
        html.AppendLine($"<span class=\"muted\">{E(ctx.NetworkSummary.Describe())}</span>");
        html.AppendLine("</div>");

        html.AppendLine("<h3>Покрытие источников</h3><table><tr><th>Источник</th><th>Статус</th><th>Записей</th><th>Лимит</th><th>Ошибка/ограничение</th></tr>");
        foreach (var source in result.Coverage.Sources)
        {
            var limit = source.Capped
                ? source.Limit > 0 ? $"достигнут ({source.Limit})" : "достигнут"
                : "нет";
            html.AppendLine($"<tr><td>{E(source.Source)}</td><td>{E(source.Status)}</td><td>{source.Count}</td><td>{limit}</td><td>{E(source.Error)}</td></tr>");
        }
        html.AppendLine("</table>");

        html.AppendLine("<h3>Устройства по типам</h3><table><tr><th>Тип</th><th>Количество</th></tr>");
        foreach (var item in ctx.DevicesByCategory)
        {
            html.AppendLine($"<tr><td>{E(item.Category)}</td><td>{item.Count}</td></tr>");
        }
        html.AppendLine("</table>");

        html.AppendLine("<h3>Доказательства по источникам</h3><table><tr><th>Источник</th><th>Записей</th></tr>");
        foreach (var item in ctx.EvidenceBySource)
        {
            html.AppendLine($"<tr><td>{E(item.Source)}</td><td>{item.Count}</td></tr>");
        }
        html.AppendLine("</table>");
    }

    private static void AppendIncidentSection(StringBuilder html, ForensicReportContext ctx)
    {
        html.AppendLine("<h2 id=\"incidents\">2. Возможные инциденты</h2>");
        html.AppendLine($"<p class=\"note\">{E(ctx.CleanupVerdict())}</p>");
        if (ctx.SuspiciousFindings.Count == 0)
        {
            AppendAttentionTable(html, ctx);
            return;
        }

        html.AppendLine("<p>Ниже — записи со статусом «Подозрительно», отсортированные по уровню риска. Их следует проверить в первую очередь.</p>");
        html.AppendLine("<table><tr><th>Дата и время</th><th>Риск</th><th>Уверенность</th><th>Инициатор</th><th>Инструмент</th><th>Где искали</th><th>Что найдено</th><th>Подробности</th></tr>");
        foreach (var finding in ctx.SuspiciousFindings)
        {
            var rowClass = finding.Severity.Equals("High", StringComparison.OrdinalIgnoreCase) ? "suspicious" : "";
            html.AppendLine(
                $"<tr class=\"{rowClass}\"><td>{E(finding.TimestampText)}</td>" +
                $"<td class=\"{E(finding.Severity.ToLowerInvariant())}\">{E(finding.AssessmentText)} / {E(finding.SeverityText)}</td>" +
                $"<td>{E(finding.ConfidenceText)}</td><td>{E(finding.InitiatorText)}</td><td>{E(finding.PossibleToolText)}</td>" +
                $"<td>{E(finding.AreaText)}</td><td>{E(finding.Finding)}</td><td>{E(finding.Details)}</td></tr>");
        }
        html.AppendLine("</table>");
        AppendAttentionTable(html, ctx);
    }

    /// <summary>
    /// Запуск утилиты работы с USB и наличие средства удаления следов не
    /// доказывают очистку и потому не попадают в таблицу подозрительных записей.
    /// Но раздел об инцидентах без них создаёт ложное впечатление, что искать
    /// нечего.
    /// </summary>
    private static void AppendAttentionTable(StringBuilder html, ForensicReportContext ctx)
    {
        if (ctx.AttentionFindings.Count == 0)
        {
            return;
        }

        html.AppendLine("<h3>Требуют внимания</h3>");
        html.AppendLine("<p>Запуск программ для работы с USB и наличие средств удаления следов. "
                        + "Сами по себе они не доказывают очистку, но проверить обстоятельства нужно.</p>");
        html.AppendLine("<table><tr><th>Дата и время</th><th>Тип действия</th><th>Риск</th><th>Инициатор</th>"
                        + "<th>Инструмент</th><th>Что найдено</th><th>Подробности</th></tr>");
        foreach (var finding in ctx.AttentionFindings)
        {
            html.AppendLine(
                $"<tr><td>{E(finding.TimestampText)}</td><td>{E(finding.ActionKindText)}</td>" +
                $"<td class=\"{E(finding.Severity.ToLowerInvariant())}\">{E(finding.SeverityText)}</td>" +
                $"<td>{E(finding.InitiatorText)}</td><td>{E(finding.PossibleToolText)}</td>" +
                $"<td>{E(finding.Finding)}</td><td>{E(finding.Details)}</td></tr>");
        }
        html.AppendLine("</table>");
    }

    private static void AppendCleanupSection(StringBuilder html, ForensicReportContext ctx)
    {
        html.AppendLine("<h2 id=\"cleanup\">3. Все признаки очистки</h2>");
        if (ctx.CleanupFindings.Count == 0)
        {
            html.AppendLine("<p>Записей не найдено.</p>");
            return;
        }

        html.AppendLine("<table><tr><th>Дата и время</th><th>Тип действия</th><th>Статус</th><th>Инициатор</th><th>Инструмент</th><th>Уверенность</th><th>Риск</th><th>Где искали</th><th>Что найдено</th><th>Подробности</th></tr>");
        foreach (var finding in ctx.CleanupFindings)
        {
            html.AppendLine(
                $"<tr><td>{E(finding.TimestampText)}</td><td>{E(finding.ActionKindText)}</td><td>{E(finding.AssessmentText)}</td><td>{E(finding.InitiatorText)}</td>" +
                $"<td>{E(finding.PossibleToolText)}</td><td>{E(finding.ConfidenceText)}</td>" +
                $"<td class=\"{E(finding.Severity.ToLowerInvariant())}\">{E(finding.SeverityText)}</td>" +
                $"<td>{E(finding.AreaText)}</td><td>{E(finding.Finding)}</td><td>{E(finding.Details)}</td></tr>");
        }
        html.AppendLine("</table>");
    }

    private static void AppendDevicesSection(StringBuilder html, ForensicReportContext ctx)
    {
        html.AppendLine("<h2 id=\"devices\">4. USB-устройства</h2>");
        html.AppendLine("<p class=\"muted\">В отчёт включены реальные USB/Type-C устройства, подтверждённые связанные USB-диски и остаточные следы usbflags. Внутренние SATA/NVMe-диски и ОЗУ не относятся к USB и исключены.</p>");
        html.AppendLine("<p class=\"muted\">Таблица перечисляет все записи реестра, а колонка «Место в списке устройств» показывает, "
                        + "какие из них Windows завела на части одного и того же устройства. Такие записи свёрнуты в своё устройство "
                        + "и в списке программы отдельной строкой не стоят.</p>");
        html.AppendLine("<table><tr><th>Canonical device</th><th>Место в списке устройств</th><th>Приносили ли с собой</th><th>Тип</th><th>Что это</th><th>Как подключалось</th><th>Внешнее или встроенное</th><th>На чём основан вывод</th><th>Технические коды</th><th>Назначение</th><th>Откуда</th><th>Имя</th><th>Производитель</th><th>Модель</th><th>VID/PID</th><th>Серийный номер</th><th>Когда подключали</th><th>Последняя активность</th><th>Когда отключали</th><th>Пояснение по датам</th><th>Расположение</th><th>Буквы дисков</th><th>Системный ID</th></tr>");
        foreach (var device in ctx.ReportableDevices)
        {
            var place = DeviceComposition.IsFoldedByDefault(device) ? "свёрнута в своё устройство" : "отдельная строка";
            html.AppendLine(
                $"<tr><td>{E(device.CanonicalDeviceId)}{(device.IsCanonicalPrimary ? " (primary)" : "")}</td>" +
                $"<td>{E(place)}</td>" +
                $"<td>{E(device.ExternalityText)}</td><td>{E(device.CategoryText)}</td>" +
                $"<td>{E(device.DeviceKindText)}</td><td>{E(device.TransportDisplayText)}</td><td>{E(device.OriginDisplayText)}</td>" +
                $"<td>{E(device.ClassificationEvidenceText)}</td><td>{E(device.ClassificationCodesText)}</td>" +
                $"<td>{E(device.UserMeaning)}</td><td>{E(device.SourceText)}</td>" +
                $"<td>{E(device.DisplayName)}</td><td>{E(device.ManufacturerText)}</td><td>{E(device.ModelText)}</td>" +
                $"<td>{E(device.VidPidText)}</td><td>{E(device.SerialText)}</td><td>{E(device.FirstConnectedText)}</td>" +
                $"<td>{E(device.LastSeenText)}</td><td>{E(device.LastDisconnectedText)}</td><td>{E(device.DateConfidenceText)}</td>" +
                $"<td>{E(device.LocationDisplayText)}</td><td>{E(device.DriveLetters)}</td><td>{E(device.DeviceInstanceId)}</td></tr>");
        }
        html.AppendLine("</table>");
    }

    /// <summary>
    /// Чем устройство оказалось в реестре. У сопряжённого телефона это перечень
    /// его услуг, и он важен сам по себе: по нему видно, что через соединение
    /// было можно — передавать файлы, читать контакты, выходить в сеть.
    /// </summary>
    private static void AppendCompositionBlock(StringBuilder html, ForensicReportContext ctx, UsbDeviceRecord device)
    {
        var parts = DeviceComposition.PartsOf(device, ctx.ReportableDevices);
        if (parts.Count == 0)
        {
            return;
        }

        html.AppendLine($"<h4>Записи Windows об этом устройстве ({parts.Count})</h4>");
        html.AppendLine("<table><tr><th>Имя</th><th>Что это за запись</th><th>Системный ID</th></tr>");
        foreach (var part in parts)
        {
            var meaning = string.IsNullOrWhiteSpace(part.UserMeaning) ? part.CategoryText : part.UserMeaning;
            html.AppendLine($"<tr><td>{E(part.OwnDisplayName)}</td><td>{E(meaning)}</td>"
                            + $"<td>{E(part.DeviceInstanceId)}</td></tr>");
        }
        html.AppendLine("</table>");
    }

    private static void AppendDossiersSection(StringBuilder html, ForensicReportContext ctx)
    {
        html.AppendLine("<h2 id=\"dossiers\">5. Досье устройств</h2>");
        html.AppendLine("<p>Для каждого устройства — полные идентификаторы и связанные доказательства из всех источников. "
                        + "Досье пишется на устройство, а не на запись реестра: записи, заведённые Windows на части "
                        + "того же устройства, перечи��лены внутри его досье, а полностью все записи стоят в таблице выше.</p>");

        foreach (var device in ctx.ListedDevices)
        {
            var related = ForensicReportContext.GetRelatedEvidence(ctx, device).ToArray();
            var correlations = ForensicReportContext.GetCorrelationEvidence(ctx, device).ToArray();

            html.AppendLine("<section class=\"card\">");
            html.AppendLine($"<h3>{E(device.DisplayName)}</h3>");
            html.AppendLine("<p>");
            html.AppendLine($"<b>Тип:</b> {E(device.CategoryText)}<br>");
            html.AppendLine($"<b>Назначение:</b> {E(device.UserMeaning)}<br>");
            html.AppendLine($"<b>Источник записи:</b> {E(device.SourceText)}<br>");
            html.AppendLine($"<b>Тип записи:</b> {E(device.DeviceTypeText)}<br>");
            html.AppendLine($"<b>Приносили ли с собой:</b> {E(device.ExternalityText)}<br>");
            html.AppendLine($"<b>Что это:</b> {E(device.DeviceKindText)}<br>");
            html.AppendLine($"<b>Как подключалось:</b> {E(device.TransportDisplayText)}<br>");
            html.AppendLine($"<b>Внешнее или встроенное:</b> {E(device.OriginDisplayText)} "
                            + $"({E(DeviceKindResolver.DescribeConfidence(device.ClassificationConfidence))})<br>");
            html.AppendLine($"<b>На чём основан вывод:</b> {E(device.ClassificationEvidenceText)}<br>");
            html.AppendLine($"<b>Технические коды классификации:</b> {E(device.ClassificationCodesText)}<br>");
            html.AppendLine($"<b>Производитель:</b> {E(device.ManufacturerText)}<br>");
            html.AppendLine($"<b>Модель:</b> {E(device.ModelText)}<br>");
            html.AppendLine($"<b>VID/PID:</b> {E(device.VidPidText)}<br>");
            html.AppendLine($"<b>Серийный номер:</b> {E(device.SerialText)}<br>");
            html.AppendLine($"<b>Доверие к идентификаторам:</b> {E(device.IdentityTrustText)}<br>");
            html.AppendLine($"<b>Container ID:</b> {E(device.ContainerId)}<br>");
            html.AppendLine($"<b>Canonical device:</b> {E(device.CanonicalDeviceId)} ({E(device.IdentityConfidence)})<br>");
            html.AppendLine($"<b>Связанные source IDs:</b> {E(string.Join("; ", device.LinkedSourceIds))}<br>");
            html.AppendLine($"<b>Когда подключали:</b> {E(device.FirstConnectedText)}<br>");
            html.AppendLine($"<b>Последняя активность:</b> {E(device.LastSeenText)}<br>");
            html.AppendLine($"<b>Когда отключали:</b> {E(device.LastDisconnectedText)}<br>");
            html.AppendLine($"<b>Пояснение по датам:</b> {E(device.DateConfidenceText)}<br>");
            html.AppendLine($"<b>Расположение:</b> {E(device.LocationDisplayText)}<br>");
            html.AppendLine($"<b>Буквы дисков:</b> {E(device.DriveLetters)}<br>");
            html.AppendLine($"<b>Подключено сейчас:</b> {(device.IsCurrentlyConnected ? "да" : "нет")}<br>");
            html.AppendLine($"<b>Системный ID:</b> {E(device.DeviceInstanceId)}");
            html.AppendLine("</p>");

            AppendCompositionBlock(html, ctx, device);

            if (correlations.Length > 0)
            {
                html.AppendLine("<h4>Корреляция</h4><ul>");
                foreach (var correlation in correlations)
                {
                    html.AppendLine($"<li><b>{E(correlation.EventId)}</b>: {E(correlation.SummaryText)}</li>");
                }
                html.AppendLine("</ul>");
            }

            html.AppendLine($"<h4>Связанные доказательства ({related.Length})</h4>");
            if (related.Length == 0)
            {
                html.AppendLine("<p class=\"muted\">Связанных записей не найдено.</p>");
            }
            else
            {
                html.AppendLine("<table><tr><th>Дата и время</th><th>Категория</th><th>Источник</th><th>Сила / уверенность</th><th>Событие</th><th>Описание</th></tr>");
                foreach (var evidence in related)
                {
                    html.AppendLine(
                        $"<tr><td>{E(evidence.TimestampText)}</td><td>{E(evidence.EvidenceCategoryText)}</td>" +
                        $"<td>{E(evidence.SourceText)}</td><td>{E(evidence.EvidenceStrength)} / {E(evidence.Confidence)}</td><td>{E(evidence.EventId)}</td>" +
                        $"<td>{E(evidence.SummaryText)}</td></tr>");
                }
                html.AppendLine("</table>");
            }

            AppendDeviceActivity(html, ctx.GetActivity(device));
            html.AppendLine("</section>");
        }
    }

    /// <summary>
    /// Что делали на устройстве. Отдельно от «связанных доказательств»: там
    /// перечислено всё, что упоминает устройство, а здесь — только действия
    /// человека, и у каждого видно основание привязки к этому устройству.
    /// </summary>
    private static void AppendDeviceActivity(StringBuilder html, DeviceActivityHistory history)
    {
        html.AppendLine($"<h4>Что делали на устройстве ({history.Entries.Count})</h4>");
        html.AppendLine($"<p class=\"muted\">{E(history.Verdict())}</p>");
        if (history.Entries.Count > 0)
        {
            html.AppendLine("<table><tr><th>Когда</th><th>Что делали</th><th>Папка или файл</th><th>Кто</th>"
                            + "<th>Почему отнесено к этому устройству</th><th>Что означает время</th>"
                            + "<th>Откуда взято</th></tr>");
            foreach (var entry in history.Entries)
            {
                html.AppendLine(
                    $"<tr><td>{E(entry.TimestampText)}</td><td>{E(entry.KindText)}</td><td>{E(entry.PathText)}</td>" +
                    $"<td>{E(entry.UserText)}</td><td>{E(entry.LinkText)}</td><td>{E(entry.TimeMeaning)}</td>" +
                    $"<td>{E(entry.SourceText)}</td></tr>");
            }

            html.AppendLine("</table>");
        }

        html.AppendLine($"<h4>Перенос файлов ({history.CopyIndications.Count})</h4>");
        html.AppendLine($"<p class=\"muted\">{E(history.CopyVerdict())}</p>");
        if (history.CopyIndications.Count == 0)
        {
            return;
        }

        html.AppendLine("<table><tr><th>Имя файла</th><th>Куда перенесли</th><th>Насколько надёжен вывод</th>"
                        + "<th>Разрыв во времени</th><th>Путь на устройстве</th><th>Когда виден на устройстве</th>"
                        + "<th>Путь на внутреннем диске</th><th>Когда виден на диске</th>"
                        + "<th>На чём основан вывод</th><th>Откуда взято</th></tr>");
        foreach (var indication in history.CopyIndications)
        {
            html.AppendLine(
                $"<tr><td>{E(indication.FileName)}</td><td>{E(indication.DirectionText)}</td>" +
                $"<td>{E(indication.ConfidenceText)}</td><td>{E(indication.GapText)}</td>" +
                $"<td>{E(indication.PathOnDevice)}</td><td>{E(indication.SeenOnDeviceText)}</td>" +
                $"<td>{E(indication.LocalPath)}</td><td>{E(indication.SeenLocallyText)}</td>" +
                $"<td>{E(indication.Basis)}</td><td>{E(indication.Source)}</td></tr>");
        }

        html.AppendLine("</table>");
    }

    private static void AppendTimelineSection(StringBuilder html, ForensicReportContext ctx)
    {
        html.AppendLine("<h2 id=\"timeline\">6. Хронология событий</h2>");
        html.AppendLine("<p>Полная временная шкала всех собранных доказательств (от новых к старым).</p>");
        html.AppendLine("<table><tr><th>Дата и время</th><th>Категория</th><th>Источник</th><th>Сила / уверенность</th><th>Событие</th><th>Устройство</th><th>Описание</th><th>Пояснение</th></tr>");
        foreach (var evidence in ctx.Timeline)
        {
            html.AppendLine(
                $"<tr><td>{E(evidence.TimestampText)}</td><td>{E(evidence.EvidenceCategoryText)}</td>" +
                $"<td>{E(evidence.SourceText)}</td><td>{E(evidence.EvidenceStrength)} / {E(evidence.Confidence)}</td><td>{E(evidence.EventId)}</td><td>{E(evidence.DeviceHintText)}</td>" +
                $"<td>{E(evidence.SummaryText)}</td><td>{E(evidence.UserExplanationText)}</td></tr>");
        }
        html.AppendLine("</table>");
    }

    private static void AppendEvidenceSection(StringBuilder html, ForensicReportContext ctx)
    {
        html.AppendLine("<h2 id=\"evidence\">7. Журнал доказательств</h2>");
        html.AppendLine("<p>Полный журнал с пояснениями и исходным текстом для детального анализа.</p>");
        html.AppendLine("<table><tr><th>Дата и время</th><th>Категория</th><th>Источник</th><th>Strength / confidence</th><th>Уровень</th><th>Событие</th><th>Устройство</th><th>Описание</th><th>Пояснение</th><th>Provenance</th><th>Исходный текст</th></tr>");
        foreach (var evidence in ctx.Timeline)
        {
            html.AppendLine(
                $"<tr><td>{E(evidence.TimestampText)}</td><td>{E(evidence.EvidenceCategoryText)}</td>" +
                $"<td>{E(evidence.SourceText)}</td><td>{E(evidence.EvidenceStrength)} / {E(evidence.Confidence)}</td><td>{E(evidence.Level)}</td><td>{E(evidence.EventId)}</td>" +
                $"<td>{E(evidence.DeviceHintText)}</td><td>{E(evidence.SummaryText)}</td>" +
                $"<td>{E(evidence.UserExplanationText)}</td><td>{E(evidence.Provenance)}</td><td>{E(ReportText.ForDisplay(evidence.RawText, 4000))}</td></tr>");
        }
        html.AppendLine("</table>");
    }

    /// <summary>
    /// Связи машины с внешним миром и то, куда по ним ходили. Раздел нужен рядом
    /// с USB по той же причине, по которой заведена вкладка: сетевая папка и
    /// сопряжённый телефон выносят данные не хуже флешки, и отчёт об одних
    /// флешках создаёт ложное впечатление, что других путей не было.
    /// </summary>
    private static void AppendNetworkSection(StringBuilder html, ForensicReportContext ctx)
    {
        var connections = ctx.NetworkConnections;
        html.AppendLine("<h2 id=\"network\">8. Сетевые подключения и куда по ним ходили</h2>");
        html.AppendLine($"<p class=\"note\">{E(ctx.NetworkSummary.Describe())}</p>");
        if (connections.Count == 0)
        {
            html.AppendLine("<p>Связей не найдено.</p>");
            return;
        }

        html.AppendLine("<table><tr><th>Как связывались</th><th>С чем именно</th><th>Кто начал</th>"
                        + "<th>Что нашлось внутри</th><th>Первое подключение</th><th>Последнее подключение</th>"
                        + "<th>Чем защищено</th><th>Через что шла связь</th><th>Адреса этой машины</th>"
                        + "<th>Учётная запись</th><th>Простыми словами</th><th>Откуда взято</th></tr>");
        foreach (var connection in connections)
        {
            var rowClass = connection.IsOutsideReach ? "suspicious" : "";
            html.AppendLine(
                $"<tr class=\"{rowClass}\"><td>{E(connection.KindText)}</td><td>{E(connection.TargetText)}</td>" +
                $"<td>{E(connection.DirectionText)}</td><td>{E(connection.ActivityText)}</td>" +
                $"<td>{E(connection.FirstSeenText)}</td><td>{E(connection.LastSeenText)}</td>" +
                $"<td>{E(connection.SecurityText)}</td><td>{E(connection.AdapterText)}</td>" +
                $"<td>{E(connection.LocalAddressesText)}</td><td>{E(connection.AccountText)}</td>" +
                $"<td>{E(connection.DetailsText)}</td><td>{E(connection.SourcesText)}</td></tr>");
        }

        html.AppendLine("</table>");

        foreach (var connection in connections.Where(x => x.Visits.Count > 0 || x.Sessions.Count > 0))
        {
            AppendNetworkConnectionCard(html, connection);
        }
    }

    private static void AppendNetworkConnectionCard(StringBuilder html, NetworkConnectionRecord connection)
    {
        html.AppendLine("<section class=\"card\">");
        html.AppendLine($"<h3>{E(connection.KindText)}: {E(connection.TargetText)}</h3>");
        html.AppendLine("<table><tr><th>Сведение</th><th>Значение</th></tr>");
        foreach (var (name, value) in NetworkConnectionFacts.Rows(connection))
        {
            html.AppendLine($"<tr><td>{E(name)}</td><td>{E(value)}</td></tr>");
        }

        html.AppendLine("</table>");

        if (connection.Visits.Count > 0)
        {
            html.AppendLine($"<h4>Куда ходили ({connection.Visits.Count})</h4>");
            html.AppendLine("<table><tr><th>Когда</th><th>Что делали</th><th>Папка, адрес или узел</th>"
                            + "<th>Подпись</th><th>Кто</th><th>Сколько раз</th><th>Что означает время</th>"
                            + "<th>Откуда взято</th><th>Ссылка на источник</th></tr>");
            foreach (var visit in connection.Visits)
            {
                html.AppendLine(
                    $"<tr><td>{E(visit.WhenText)}</td><td>{E(visit.KindText)}</td><td>{E(visit.TargetText)}</td>" +
                    $"<td>{E(visit.TitleText)}</td><td>{E(visit.UserText)}</td><td>{E(visit.CountText)}</td>" +
                    $"<td>{E(visit.TimeMeaning)}</td><td>{E(visit.SourceText)}</td><td>{E(visit.Provenance)}</td></tr>");
            }

            html.AppendLine("</table>");
        }

        if (connection.Sessions.Count > 0)
        {
            html.AppendLine($"<h4>Сеансы связи ({connection.Sessions.Count})</h4>");
            html.AppendLine("<table><tr><th>Подключение</th><th>Отключение</th><th>Сколько держалось</th>"
                            + "<th>Чем закончилось</th><th>Подробности</th><th>Учётная запись</th>"
                            + "<th>Откуда взято</th></tr>");
            foreach (var session in connection.Sessions)
            {
                html.AppendLine(
                    $"<tr><td>{E(session.StartedText)}</td><td>{E(session.EndedText)}</td>" +
                    $"<td>{E(session.DurationText)}</td><td>{E(session.OutcomeText)}</td>" +
                    $"<td>{E(session.ReasonText)}</td><td>{E(session.Account)}</td>" +
                    $"<td>{E(session.SourceText)}</td></tr>");
            }

            html.AppendLine("</table>");
        }

        html.AppendLine("</section>");
    }

    private static void AppendNetworkEnvironmentSection(StringBuilder html, ForensicReportContext ctx)
    {
        var env = ctx.NetworkEnvironment;
        html.AppendLine("<h2 id=\"network-environment\">9. Обстановка вокруг машины (снимок)</h2>");
        html.AppendLine($"<p class=\"note\">{E(env.Describe())}</p>");
        if (env.IsEmpty)
        {
            html.AppendLine("<p>Снимок не делался. Его можно получить кнопкой «Снять обстановку» на вкладке «Сетевые подключения».</p>");
            return;
        }

        if (env.Warnings.Count > 0)
        {
            html.AppendLine("<ul>");
            foreach (var warning in env.Warnings)
            {
                html.AppendLine($"<li>{E(warning)}</li>");
            }
            html.AppendLine("</ul>");
        }

        html.AppendLine("<h3>Wi-Fi в эфире</h3>");
        if (env.WirelessNetworks.Count == 0)
        {
            html.AppendLine("<p>Сетей Wi-Fi не слышно.</p>");
        }
        else
        {
            html.AppendLine("<table><tr><th>SSID</th><th>Связь с машиной</th><th>Сигнал</th><th>Канал</th>"
                            + "<th>Защита</th><th>BSSID</th><th>Производитель AP</th><th>Адаптер</th></tr>");
            foreach (var network in env.WirelessNetworks)
            {
                html.AppendLine(
                    $"<tr><td>{E(network.SsidText)}</td><td>{E(network.RelationText)}</td>" +
                    $"<td>{E(network.SignalText)}</td><td>{E(network.ChannelText)}</td>" +
                    $"<td>{E(network.SecurityText)}</td><td>{E(network.BssidText)}</td>" +
                    $"<td>{E(network.VendorText)}</td><td>{E(network.Adapter)}</td></tr>");
            }
            html.AppendLine("</table>");
        }

        html.AppendLine("<h3>Устройства в текущей сети</h3>");
        if (env.Neighbors.Count == 0)
        {
            html.AppendLine("<p>Устройств не найдено.</p>");
        }
        else
        {
            html.AppendLine("<table><tr><th>Роль</th><th>IP</th><th>MAC</th><th>Имя</th><th>Откуда имя</th>"
                            + "<th>Производитель</th><th>Как найдено</th><th>Состояние</th><th>Сеть</th></tr>");
            foreach (var neighbor in env.Neighbors)
            {
                html.AppendLine(
                    $"<tr><td>{E(neighbor.RoleText)}</td><td>{E(neighbor.AddressText)}</td>" +
                    $"<td>{E(neighbor.MacText)}</td><td>{E(neighbor.NameText)}</td>" +
                    $"<td>{E(neighbor.NameSourceText)}</td>" +
                    $"<td>{E(neighbor.VendorText)}</td><td>{E(neighbor.DiscoveryText)}</td>" +
                    $"<td>{E(neighbor.StateText)}</td><td>{E(neighbor.NetworkText)}</td></tr>");
            }
            html.AppendLine("</table>");
        }
    }

    private static void AppendWarningsSection(StringBuilder html, AuditResult result)
    {
        html.AppendLine("<h2 id=\"warnings\">10. Предупреждения и ограничения сбора</h2>");
        if (result.SourceWarnings.Count == 0)
        {
            html.AppendLine("<p class=\"note\">Предупреждений нет — все основные источники прочитаны успешно.</p>");
            return;
        }

        html.AppendLine("<div class=\"warn\"><ul>");
        foreach (var warning in result.SourceWarnings)
        {
            html.AppendLine($"<li>{E(warning)}</li>");
        }
        html.AppendLine("</ul></div>");
    }

    private static void AppendMethodologySection(StringBuilder html)
    {
        html.AppendLine("<h2 id=\"methodology\">11. Источники данных</h2>");
        html.AppendLine("""
            <ul>
            <li>Реестр Windows: USB, USBSTOR, SCSI/UASP, WPD/MTP, USB4 и только релевантные Thunderbolt PCI instances, MountedDevices.</li>
            <li>Журнал setupapi.dev.log — установка и удаление устройств.</li>
            <li>Журналы Windows: System, Security, DeviceSetupManager, DriverFrameworks-UserMode.</li>
            <li>Журнал корпоративной защиты USB (если установлен).</li>
            <li>Пользовательские артефакты: Recent, LNK, Jump Lists, MountPoints2, MRU.</li>
            <li>Offline-анализ NTUSER.DAT и UsrClass.dat (при доступе).</li>
            <li>Execution/presence artifacts: Prefetch supports execution; BAM/DAM and PCA can corroborate activity; Amcache and Windows 10/11 Shimcache are treated as presence/inventory unless stronger evidence exists.</li>
            <li>Корреляция устройств с доказательствами по VID/PID, серийному номеру и Instance ID.</li>
            <li>Сетевые связи: список сетей и их подписи в реестре, параметры сетевых подключений, профили Wi-Fi, сопряжения Bluetooth.</li>
            <li>Журналы сетей: WLAN-AutoConfig, NetworkProfile, SMBClient, TerminalServices, RasClient.</li>
            <li>Куда ходили по сети: сетевые диски, введённые пути, запомненные папки, ярлыки, списки переходов, история браузеров и их загрузки.</li>
            </ul>
            <p class="muted">Все даты указаны в московском времени (МСК). Отчёт сформирован автоматически по результатам одного полного сканирования.</p>
            """);
    }

    private static void AppendExternalUtilitiesSection(StringBuilder html, ExternalUtilityReportSnapshot snapshot)
    {
        html.AppendLine("<h2 id=\"external-utils\">11. Сторонние утилиты</h2>");
        html.AppendLine($"<p>Снимок окна/разбора: {E(DateDisplay.FormatMoscow(snapshot.CapturedAtUtc))}. Утилита: {E(snapshot.UtilityName ?? "не указана")}.</p>");

        if (snapshot.HistoricalLaunches.Count > 0)
        {
            html.AppendLine("<h3>Исторические запуски USB-утилит</h3><table><tr><th>Дата</th><th>Утилита</th><th>Источник</th><th>Описание</th></tr>");
            foreach (var launch in snapshot.HistoricalLaunches)
            {
                html.AppendLine($"<tr><td>{E(launch.TimestampText)}</td><td>{E(launch.ToolName)}</td><td>{E(launch.Source)}</td><td>{E(launch.Summary)}</td></tr>");
            }
            html.AppendLine("</table>");
        }

        if (snapshot.Rows.Count > 0)
        {
            html.AppendLine("<h3>Считанные строки из окна утилиты</h3><table><tr><th>Раздел</th><th>Запись</th><th>Данные</th><th>Разбор</th></tr>");
            foreach (var row in snapshot.Rows)
            {
                html.AppendLine(
                    $"<tr><td>{E(row.SectionTitle)}</td><td>{E(row.PrimaryText)}</td><td>{E(row.DetailsText)}</td><td>{E(row.AnalysisText)}</td></tr>");
            }
            html.AppendLine("</table>");
        }
    }

    private static string E(string? value) => WebUtility.HtmlEncode(value ?? "");
}
