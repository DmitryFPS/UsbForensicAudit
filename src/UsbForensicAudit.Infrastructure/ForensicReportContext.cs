namespace UsbForensicAudit;

internal sealed class ForensicReportContext
{
    public ForensicReportContext(AuditResult result, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null, DevicePolicy? policy = null, CaseMetadata? caseMetadata = null)
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
            .OrderByDescending(x => ReportSeverity.Rank(x.Severity))
            .ThenByDescending(x => x.TimestampUtc)
            .ToArray();
        HighRiskFindings = SuspiciousFindings
            .Where(x => x.Severity.Equals("High", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        AttentionFindings = CleanupFindings
            .Where(x => x.NeedsAttention)
            .OrderByDescending(x => ReportSeverity.Rank(x.Severity))
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
        Exfiltration = ExfiltrationAnalyzer.Analyze(result);
        // policy == null на реальном прогоне: политику берём из файла рядом с
        // программой. Тесты передают политику явно и на диск не ходят.
        PolicySummary = DevicePolicyEvaluator.Evaluate(result, policy ?? DevicePolicyProvider.LoadDefault());
        Case = caseMetadata ?? CaseMetadataProvider.LoadDefault();
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

    /// <summary>Сводка «ушли ли данные наружу» — файлы, вынесенные на съёмные носители.</summary>
    public ExfiltrationSummary Exfiltration { get; }

    /// <summary>Соответствие политике допустимых устройств (device-policy.json).</summary>
    public DevicePolicySummary PolicySummary { get; }

    /// <summary>Карточка дела (chain of custody) из case.json.</summary>
    public CaseMetadata Case { get; }

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

    public static ForensicReportContext Create(AuditResult result, ExternalUtilityReportSnapshot? externalUtilitySnapshot = null, DevicePolicy? policy = null, CaseMetadata? caseMetadata = null) =>
        new(result, externalUtilitySnapshot, policy, caseMetadata);

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
        // Находки делятся на два сорта: полноценный поиск по буквам дисков и
        // серийникам томов — и попутные упоминания устройства в журналах
        // системы (Shimcache, Jump Lists). Смешивать их в одно «X из Y»
        // нельзя: упоминаний может оказаться больше, чем «искомых» устройств,
        // и фраза выродится в бессмыслицу вроде «по 8 устройствам из 4».
        var withActivity = DevicesWithActivity().ToArray();
        var searchable = ListedDevices.Count(x => GetActivity(x).CanSearchFileActivity);
        var bySearch = withActivity.Count(x => x.History.CanSearchFileActivity);
        var byMention = withActivity.Length - bySearch;
        var actions = withActivity.Sum(x => x.History.Entries.Count);
        var unsearchable = ListedDevices.Count - searchable;
        var mentionTail = byMention > 0
            ? $" Ещё по {byMention} устройствам найдены упоминания в журналах системы "
              + "(запуски программ, открытия папок): полный поиск по ним был невозможен, "
              + "и такие находки — примета присутствия устройства, а не восстановленная работа с файлами."
            : "";
        var tail = unsearchable > 0
            ? $" У {unsearchable} устройств нет буквы диска, серийного номера тома или видимого имени, "
              + "поэтому следы работы с файлами по ним искать нечем."
            : "";

        if (withActivity.Length == 0)
        {
            return $"Следов работы с файлами не найдено ни по одному из {searchable} устройств, "
                   + "по которым поиск был возможен." + tail;
        }

        var lead = bySearch > 0
            ? $"Восстановлена работа с файлами по {bySearch} устройствам из {searchable}, "
              + "по которым поиск был возможен"
            : $"Полноценный поиск по {searchable} устройствам работы с файлами не выявил";
        return $"{lead}: всего {actions} действий с учётом упоминаний." + mentionTail + tail;
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

}
