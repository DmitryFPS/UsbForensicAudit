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
    }

    public AuditResult Result { get; }
    public ExternalUtilityReportSnapshot? ExternalUtilitySnapshot { get; }
    public IReadOnlyList<CleanupFinding> CleanupFindings { get; }
    public IReadOnlyList<CleanupFinding> SuspiciousFindings { get; }
    public IReadOnlyList<CleanupFinding> HighRiskFindings { get; }
    public IReadOnlyList<EvidenceRecord> Timeline { get; }
    public IReadOnlyList<UsbDeviceRecord> ReportableDevices { get; }
    public IReadOnlyList<UsbDeviceRecord> RealDevices { get; }
    public IReadOnlyList<(string Source, int Count)> EvidenceBySource { get; }
    public IReadOnlyList<(string Category, int Count)> DevicesByCategory { get; }

    public int SuspiciousCount => SuspiciousFindings.Count;
    public int HighRiskCount => HighRiskFindings.Count;

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
               || value.Contains("WPD", StringComparison.OrdinalIgnoreCase)
               || value.Contains("USB4", StringComparison.OrdinalIgnoreCase)
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
        html.AppendLine($"<span class=\"muted\">{E(result.OsInstallGraceNote)}</span>");
        html.AppendLine("</div>");

        html.AppendLine("<nav class=\"toc\"><b>Содержание</b><ul>");
        html.AppendLine("<li><a href=\"#summary\">1. Сводка для расследования</a></li>");
        html.AppendLine("<li><a href=\"#incidents\">2. Возможные инциденты</a></li>");
        html.AppendLine("<li><a href=\"#cleanup\">3. Все признаки очистки</a></li>");
        html.AppendLine("<li><a href=\"#devices\">4. USB-устройства</a></li>");
        html.AppendLine("<li><a href=\"#dossiers\">5. Досье устройств</a></li>");
        html.AppendLine("<li><a href=\"#timeline\">6. Хронология событий</a></li>");
        html.AppendLine("<li><a href=\"#evidence\">7. Журнал доказательств</a></li>");
        html.AppendLine("<li><a href=\"#warnings\">8. Предупреждения и ограничения</a></li>");
        html.AppendLine("<li><a href=\"#methodology\">9. Источники данных</a></li>");
        if (ctx.ExternalUtilitySnapshot is not null && (ctx.ExternalUtilitySnapshot.Rows.Count > 0 || ctx.ExternalUtilitySnapshot.HistoricalLaunches.Count > 0))
        {
            html.AppendLine("<li><a href=\"#external-utils\">10. Сторонние утилиты</a></li>");
        }
        html.AppendLine("</ul></nav>");

        AppendSummarySection(html, ctx);
        AppendIncidentSection(html, ctx);
        AppendCleanupSection(html, ctx);
        AppendDevicesSection(html, ctx);
        AppendDossiersSection(html, ctx);
        AppendTimelineSection(html, ctx);
        AppendEvidenceSection(html, ctx);
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
        html.AppendLine($"<b>USB/Type-C записей:</b> {ctx.ReportableDevices.Count}; ");
        html.AppendLine($"<b>реальных USB:</b> {ctx.RealDevices.Count}; ");
        html.AppendLine($"<b>USB-доказательств:</b> {ctx.Timeline.Count}; ");
        html.AppendLine($"<b>релевантных признаков очистки:</b> {ctx.CleanupFindings.Count}; ");
        html.AppendLine($"<b>подозрительных:</b> {ctx.SuspiciousCount}; ");
        html.AppendLine($"<b>высокого риска:</b> {ctx.HighRiskCount}; ");
        html.AppendLine($"<b>предупреждений:</b> {result.SourceWarnings.Count}; ");
        html.AppendLine($"<b>canonical devices с точной датой:</b> {result.Coverage.CanonicalDevicesWithExactDates}/{result.Coverage.CanonicalDeviceCount} ({result.Coverage.ExactDateCoveragePercent:0.##}%)");
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
        if (ctx.SuspiciousFindings.Count == 0)
        {
            html.AppendLine("<p class=\"note\">Подозрительных признаков очистки или сокрытия следов не обнаружено.</p>");
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
        html.AppendLine("<table><tr><th>Canonical device</th><th>Тип</th><th>Transport / connection / classification</th><th>Confidence / evidence</th><th>Что это</th><th>Откуда</th><th>Имя</th><th>Производитель</th><th>Модель</th><th>VID/PID</th><th>Серийный номер</th><th>Когда подключали</th><th>Последняя активность</th><th>Когда отключали</th><th>Пояснение по датам</th><th>Расположение</th><th>Буквы дисков</th><th>Системный ID</th></tr>");
        foreach (var device in ctx.ReportableDevices)
        {
            html.AppendLine(
                $"<tr><td>{E(device.CanonicalDeviceId)}{(device.IsCanonicalPrimary ? " (primary)" : "")}</td><td>{E(device.CategoryText)}</td><td>{E(device.ClassificationDisplayText)}</td><td>{E(device.ClassificationEvidenceText)}</td><td>{E(device.UserMeaning)}</td><td>{E(device.SourceText)}</td>" +
                $"<td>{E(device.DisplayName)}</td><td>{E(device.ManufacturerText)}</td><td>{E(device.ModelText)}</td>" +
                $"<td>{E(device.VidPidText)}</td><td>{E(device.SerialText)}</td><td>{E(device.FirstConnectedText)}</td>" +
                $"<td>{E(device.LastSeenText)}</td><td>{E(device.LastDisconnectedText)}</td><td>{E(device.DateConfidenceText)}</td>" +
                $"<td>{E(device.LocationDisplayText)}</td><td>{E(device.DriveLetters)}</td><td>{E(device.DeviceInstanceId)}</td></tr>");
        }
        html.AppendLine("</table>");
    }

    private static void AppendDossiersSection(StringBuilder html, ForensicReportContext ctx)
    {
        html.AppendLine("<h2 id=\"dossiers\">5. Досье устройств</h2>");
        html.AppendLine("<p>Для каждого устройства — полные идентификаторы и связанные доказательства из всех источников.</p>");

        foreach (var device in ctx.ReportableDevices)
        {
            var related = ForensicReportContext.GetRelatedEvidence(ctx, device).ToArray();
            var correlations = ForensicReportContext.GetCorrelationEvidence(ctx, device).ToArray();

            html.AppendLine("<section class=\"card\">");
            html.AppendLine($"<h3>{E(device.DisplayName)}</h3>");
            html.AppendLine("<p>");
            html.AppendLine($"<b>Тип:</b> {E(device.CategoryText)}<br>");
            html.AppendLine($"<b>Назначение:</b> {E(device.UserMeaning)}<br>");
            html.AppendLine($"<b>Источник записи:</b> {E(device.SourceText)}<br>");
            html.AppendLine($"<b>Тип устройства:</b> {E(device.DeviceTypeText)}<br>");
            html.AppendLine($"<b>Transport / connection / classification:</b> {E(device.ClassificationDisplayText)}<br>");
            html.AppendLine($"<b>Classification evidence:</b> {E(device.ClassificationEvidenceText)}<br>");
            html.AppendLine($"<b>Производитель:</b> {E(device.ManufacturerText)}<br>");
            html.AppendLine($"<b>Модель:</b> {E(device.ModelText)}<br>");
            html.AppendLine($"<b>VID/PID:</b> {E(device.VidPidText)}<br>");
            html.AppendLine($"<b>Серийный номер:</b> {E(device.SerialText)}<br>");
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
                html.AppendLine("<table><tr><th>Дата и время</th><th>Категория</th><th>Источник</th><th>Событие</th><th>Описание</th></tr>");
                foreach (var evidence in related)
                {
                    html.AppendLine(
                        $"<tr><td>{E(evidence.TimestampText)}</td><td>{E(evidence.EvidenceCategoryText)}</td>" +
                        $"<td>{E(evidence.SourceText)}</td><td>{E(evidence.EventId)}</td>" +
                        $"<td>{E(evidence.SummaryText)}</td></tr>");
                }
                html.AppendLine("</table>");
            }

            html.AppendLine("</section>");
        }
    }

    private static void AppendTimelineSection(StringBuilder html, ForensicReportContext ctx)
    {
        html.AppendLine("<h2 id=\"timeline\">6. Хронология событий</h2>");
        html.AppendLine("<p>Полная временная шкала всех собранных доказательств (от новых к старым).</p>");
        html.AppendLine("<table><tr><th>Дата и время</th><th>Категория</th><th>Источник</th><th>Событие</th><th>Устройство</th><th>Описание</th><th>Пояснение</th></tr>");
        foreach (var evidence in ctx.Timeline)
        {
            html.AppendLine(
                $"<tr><td>{E(evidence.TimestampText)}</td><td>{E(evidence.EvidenceCategoryText)}</td>" +
                $"<td>{E(evidence.SourceText)}</td><td>{E(evidence.EventId)}</td><td>{E(evidence.DeviceHintText)}</td>" +
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

    private static void AppendWarningsSection(StringBuilder html, AuditResult result)
    {
        html.AppendLine("<h2 id=\"warnings\">8. Предупреждения и ограничения сбора</h2>");
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
        html.AppendLine("<h2 id=\"methodology\">9. Источники данных</h2>");
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
            </ul>
            <p class="muted">Все даты указаны в московском времени (МСК). Отчёт сформирован автоматически по результатам одного полного сканирования.</p>
            """);
    }

    private static void AppendExternalUtilitiesSection(StringBuilder html, ExternalUtilityReportSnapshot snapshot)
    {
        html.AppendLine("<h2 id=\"external-utils\">10. Сторонние утилиты</h2>");
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
