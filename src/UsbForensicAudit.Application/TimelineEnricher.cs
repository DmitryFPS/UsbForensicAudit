namespace UsbForensicAudit;

public sealed class TimelineEnricher
{
    private readonly IConnectedDeviceProbe _connectedDeviceProbe;

    public TimelineEnricher()
        : this(NullConnectedDeviceProbe.Instance)
    {
    }

    public TimelineEnricher(IConnectedDeviceProbe connectedDeviceProbe)
    {
        _connectedDeviceProbe = connectedDeviceProbe;
    }

    public void Enrich(AuditResult result)
    {
        var connectedDevices = _connectedDeviceProbe.Capture();
        var scanStartedUtc = result.StartedAtUtc;

        foreach (var evidence in result.Evidence)
        {
            SanitizeEvidence(evidence);

            if (string.IsNullOrWhiteSpace(evidence.EvidenceCategory))
            {
                evidence.EvidenceCategory = ClassifyEvidence(evidence);
            }

            if (string.IsNullOrWhiteSpace(evidence.UserExplanation))
            {
                evidence.UserExplanation = ExplainEvidence(evidence);
            }
            else if (string.IsNullOrWhiteSpace(TextSanitizer.NormalizeDisplay(evidence.UserExplanation, 800)))
            {
                evidence.UserExplanation = ExplainEvidence(evidence);
            }
        }

        foreach (var device in result.Devices)
        {
            EnrichDevice(device, result.Evidence, connectedDevices, scanStartedUtc);
        }

        for (var i = 0; i < result.SourceWarnings.Count; i++)
        {
            result.SourceWarnings[i] = TextSanitizer.NormalizeDisplay(result.SourceWarnings[i], 500);
        }
    }

    private static void SanitizeEvidence(EvidenceRecord evidence)
    {
        evidence.Source = Sanitize(evidence.Source, 220);
        evidence.EvidenceCategory = Sanitize(evidence.EvidenceCategory, 220);
        evidence.UserExplanation = Sanitize(evidence.UserExplanation, 800);
        evidence.EventId = Sanitize(evidence.EventId, 120);
        evidence.Level = Sanitize(evidence.Level, 120);
        evidence.Provider = Sanitize(evidence.Provider, 220);
        evidence.Channel = Sanitize(evidence.Channel, 220);
        evidence.Computer = Sanitize(evidence.Computer, 220);
        evidence.SourceFile = Sanitize(evidence.SourceFile, 800);
        evidence.SourceRecord = Sanitize(evidence.SourceRecord, 220);
        evidence.DeviceHint = Sanitize(evidence.DeviceHint, 500);
        evidence.Summary = Sanitize(evidence.Summary, 800);
        evidence.RawText = Sanitize(evidence.RawText, 4000);
    }

    /// <summary>
    /// Непустое исходное значение не должно исчезать из-за эвристик читаемости:
    /// в худшем случае показываем его с удалёнными управляющими символами.
    /// </summary>
    private static string Sanitize(string value, int maxLength)
    {
        var normalized = TextSanitizer.NormalizeDisplay(value, maxLength);
        if (!string.IsNullOrWhiteSpace(normalized) || string.IsNullOrWhiteSpace(value))
        {
            return normalized;
        }

        return TextSanitizer.CleanIdentifier(value, maxLength);
    }

    private static void EnrichDevice(UsbDeviceRecord device, IReadOnlyList<EvidenceRecord> evidence, ConnectedDeviceIndex connectedDevices, DateTimeOffset scanStartedUtc)
    {
        if (device.VisualCategory is "SupportArtifact" or "UsbFlagsTrace")
        {
            device.IsCurrentlyConnected = false;
            device.DisconnectDisplayKind = "NotApplicable";
            device.DateConfidence = device.DeviceType.Equals("USBFlags", StringComparison.OrdinalIgnoreCase)
                ? "Остаточный след usbflags. Последняя активность — ориентировочное время изменения ключа реестра; точное подключение этим источником не подтверждается."
                : "Служебная запись Windows — даты подключения здесь не показываются.";
            return;
        }

        device.IsCurrentlyConnected = connectedDevices.IsConnected(device) || device.IsCurrentlyConnected;

        var tokens = BuildTokens(device).ToArray();
        var timelineMatches = FindTimelineMatches(evidence, tokens);

        var connectionMatches = timelineMatches
            .Where(IsConnectionEvidence)
            .OrderBy(x => x.TimestampUtc)
            .ToArray();

        var disconnectMatches = timelineMatches
            .Where(IsDisconnectEvidence)
            .OrderBy(x => x.TimestampUtc)
            .ToArray();

        device.Sessions = ConnectionSessionBuilder.Build(
            connectionMatches.Select(x => (x.TimestampUtc, IsConnect: true, EvidenceProvenance(x)))
                .Concat(disconnectMatches.Select(x => (x.TimestampUtc, IsConnect: false, EvidenceProvenance(x)))))
            .ToList();

        if (connectionMatches.Length > 0)
        {
            if (!device.FirstConnectedUtc.HasValue
                || !device.ConnectionDisplayKind.Equals("PnpDevProperty", StringComparison.OrdinalIgnoreCase))
            {
                device.FirstConnectedUtc = connectionMatches.First().TimestampUtc;
                device.ConnectionDisplayKind = "ExactEvent";
                device.FirstConnectedProvenance = EvidenceProvenance(connectionMatches.First());
            }

            SetLastSeen(device, timelineMatches);
            device.DateConfidence = AppendConfidence(
                device.DateConfidence,
                "Даты дополнены из журнала Windows и setupapi.dev.log.");
        }
        else if (timelineMatches.Length > 0)
        {
            SetLastSeen(device, timelineMatches);
            device.DateConfidence = AppendConfidence(
                device.DateConfidence,
                "Устройство видно в системном журнале.");
        }
        else if (!device.FirstConnectedUtc.HasValue
                 && !device.LastSeenUtc.HasValue
                 && !device.LastDisconnectedUtc.HasValue)
        {
            device.DateConfidence = "Windows помнит устройство, но когда его подключали — неизвестно.";
        }

        ApplyLiveConnectionFallback(device, scanStartedUtc);

        if (disconnectMatches.Length > 0)
        {
            var eventDisconnect = disconnectMatches.Last().TimestampUtc;
            if (!device.LastDisconnectedUtc.HasValue || eventDisconnect > device.LastDisconnectedUtc)
            {
                device.LastDisconnectedUtc = eventDisconnect;
                device.DisconnectDisplayKind = "ExactEvent";
                device.LastDisconnectedProvenance = EvidenceProvenance(disconnectMatches.Last());
            }

            if (device.IsCurrentlyConnected)
            {
                device.DateConfidence += " Сейчас устройство снова подключено.";
            }

            return;
        }

        if (device.LastDisconnectedUtc.HasValue
            && device.DisconnectDisplayKind.Equals("PnpDevProperty", StringComparison.OrdinalIgnoreCase))
        {
            if (device.IsCurrentlyConnected)
            {
                device.DateConfidence = AppendConfidence(device.DateConfidence, "Сейчас устройство снова подключено.");
            }

            return;
        }

        if (device.IsCurrentlyConnected)
        {
            device.DisconnectDisplayKind = "ConnectedNow";
            return;
        }

        if (device.LastSeenUtc.HasValue)
        {
            device.LastDisconnectedUtc = device.LastSeenUtc;
            device.DisconnectDisplayKind = "LastActivityEstimate";
            device.LastDisconnectedProvenance = string.IsNullOrWhiteSpace(device.LastSeenProvenance)
                ? "Оценка по последней активности устройства"
                : $"Оценка по последней активности: {device.LastSeenProvenance}";
            device.DateConfidence = string.IsNullOrWhiteSpace(device.DateConfidence)
                ? "Точное отключение не найдено. Показана дата последней активности — устройство сейчас не подключено."
                : device.DateConfidence + " Отключение оценено по последней активности.";
            return;
        }

        device.DisconnectDisplayKind = "NotConnectedUnknown";
        device.DateConfidence = string.IsNullOrWhiteSpace(device.DateConfidence)
            ? "Устройство сейчас не подключено, но точное время отключения не найдено."
            : device.DateConfidence + " Сейчас не подключено.";
    }

    private static EvidenceRecord[] FindTimelineMatches(IReadOnlyList<EvidenceRecord> evidence, string[] tokens)
    {
        return evidence
            .Where(e => tokens.Any(t => ContainsToken(e, t)))
            .Where(e => DateDisplay.IsReliable(e.TimestampUtc))
            .Where(e => e.CanEstablishConnectionDate)
            .Where(e => !e.EvidenceCategory.Contains("Очистка", StringComparison.OrdinalIgnoreCase))
            .Where(IsExactDeviceTimelineEvidence)
            .ToArray();
    }

    private static void ApplyLiveConnectionFallback(UsbDeviceRecord device, DateTimeOffset scanStartedUtc)
    {
        if (!device.IsCurrentlyConnected || device.FirstConnectedUtc.HasValue)
        {
            if (device.IsCurrentlyConnected)
            {
                var previous = device.LastSeenUtc;
                device.LastSeenUtc = Max(device.LastSeenUtc, scanStartedUtc);
                if (device.LastSeenUtc != previous)
                {
                    device.LastSeenProvenance = ScanProvenance(scanStartedUtc);
                }
            }

            return;
        }

        if (device.RegistryLastWriteUtc.HasValue)
        {
            device.FirstConnectedUtc = device.RegistryLastWriteUtc;
            device.ConnectionDisplayKind = "RegistryActivity";
            device.FirstConnectedProvenance = "Время последнего изменения записи устройства в реестре";
            device.LastSeenUtc = Max(device.LastSeenUtc, scanStartedUtc);
            device.LastSeenProvenance = ScanProvenance(scanStartedUtc);
            device.DateConfidence =
                "Устройство подключено сейчас. Точные журналы Windows недоступны (часто из-за DLP). Дата взята из изменения записи в реестре.";
            return;
        }

        device.FirstConnectedUtc = scanStartedUtc;
        device.ConnectionDisplayKind = "LiveAtScan";
        device.FirstConnectedProvenance = ScanProvenance(scanStartedUtc);
        device.LastSeenUtc = scanStartedUtc;
        device.LastSeenProvenance = ScanProvenance(scanStartedUtc);
        device.DateConfidence =
            "Устройство подключено сейчас и обнаружено при сканировании. Показано время сканирования: "
            + "оно доказывает, что устройство было подключено в этот момент, но не говорит, когда его подключили. "
            + "DLP может скрывать обычные следы Windows.";
    }

    /// <summary>
    /// Дата без указания источника в отчёте выглядит как установленный факт.
    /// Время сканирования — тоже наблюдение, и назвать его надо прямо.
    /// </summary>
    private static string ScanProvenance(DateTimeOffset scanStartedUtc) =>
        $"Живой опрос системы во время сканирования {DateDisplay.FormatMoscow(scanStartedUtc)}";

    private static void SetLastSeen(UsbDeviceRecord device, IReadOnlyList<EvidenceRecord> matches)
    {
        var latest = matches.OrderByDescending(x => x.TimestampUtc).First();
        if (!device.LastSeenUtc.HasValue || latest.TimestampUtc > device.LastSeenUtc.Value)
        {
            device.LastSeenUtc = latest.TimestampUtc;
            device.LastSeenProvenance = EvidenceProvenance(latest);
        }
    }

    /// <summary>
    /// Называет конкретную запись-источник, а не только её вид: по ней дату можно
    /// перепроверить и увидеть, что она относится именно к этому устройству.
    /// </summary>
    private static string EvidenceProvenance(EvidenceRecord evidence)
    {
        var parts = new[]
        {
            evidence.Source,
            string.IsNullOrWhiteSpace(evidence.EventId) ? "" : $"событие {evidence.EventId}",
            string.IsNullOrWhiteSpace(evidence.DeviceHint) ? "" : evidence.DeviceHint
        };

        return string.Join(" | ", parts.Where(x => !string.IsNullOrWhiteSpace(x)));
    }

    private static DateTimeOffset Max(DateTimeOffset? current, DateTimeOffset candidate)
    {
        return current.HasValue ? (current.Value > candidate ? current.Value : candidate) : candidate;
    }

    private static string AppendConfidence(string current, string addition)
    {
        if (string.IsNullOrWhiteSpace(current))
        {
            return addition;
        }

        return current.Contains(addition, StringComparison.OrdinalIgnoreCase)
            ? current
            : $"{current} {addition}";
    }

    private static IEnumerable<string> BuildTokens(UsbDeviceRecord device)
    {
        return DeviceEvidenceTokens.Build(device);
    }

    private static bool ContainsToken(EvidenceRecord evidence, string token)
    {
        return DeviceEvidenceTokens.Contains(evidence, token);
    }

    private static bool IsConnectionEvidence(EvidenceRecord evidence)
    {
        if (IsDisconnectEvidence(evidence))
        {
            return false;
        }

        return evidence.EvidenceCategory.StartsWith("Подключение", StringComparison.OrdinalIgnoreCase)
               || evidence.EvidenceCategory.StartsWith(EndpointProtectionCategories.Connect, StringComparison.OrdinalIgnoreCase)
               || evidence.EventId == "6416"
               || evidence.EvidenceCategory.Contains("Установка/инициализация", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsExactDeviceTimelineEvidence(EvidenceRecord evidence)
    {
        if (evidence.Source.Equals("Correlation", StringComparison.OrdinalIgnoreCase)
            || evidence.EvidenceCategory.Contains("Пользовательская", StringComparison.OrdinalIgnoreCase)
            || evidence.EvidenceCategory.Contains("Запуск", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (evidence.Source.Contains("setupapi", StringComparison.OrdinalIgnoreCase))
        {
            return IsDisconnectEvidence(evidence) || evidence.EvidenceCategory.Contains("Установка", StringComparison.OrdinalIgnoreCase);
        }

        return IsConnectionEvidence(evidence) || IsDisconnectEvidence(evidence);
    }

    /// <summary>
    /// Подстроки, которые содержат «слова отключения», но отключением не являются.
    /// Они вырезаются из текста ДО проверки, чтобы событие подключения не было
    /// ложно классифицировано как отключение (это ломало сеансы и FirstConnected):
    /// - "RemovalPolicy" — штатное свойство в XML почти любого PnP-события установки;
    /// - "removed from ... queue" — формулировка событий установки драйвера;
    /// - "удаленн..." (двойное «н») — «удалённый доступ/устройство» (remote), а не «удалено».
    /// </summary>
    private static readonly System.Text.RegularExpressions.Regex FalseDisconnectContext = new(
        @"removal\s*policy|removed\s+from\s+(?:the\s+)?[\w\s]{0,30}queue|удал[её]нн\w*",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase
        | System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// Слова отключения ищутся по границам слов, а не подстрокой: раньше
    /// "удален" совпадало внутри «удаленного доступа», а "removal" — внутри
    /// "RemovalPolicy", и подключения превращались в отключения.
    /// </summary>
    private static readonly System.Text.RegularExpressions.Regex DisconnectWordPattern = new(
        @"\bdisconnect(?:ed|ion)?\b|\bremov(?:ed|al)\b|\buninstall(?:ed|ation)?\b|отключ|\bудал[её]н(?:[оаы])?\b|извлеч|извлек",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase
        | System.Text.RegularExpressions.RegexOptions.Compiled);

    private static bool IsDisconnectEvidence(EvidenceRecord evidence)
    {
        return evidence.EvidenceCategory.Contains("Отключение", StringComparison.OrdinalIgnoreCase)
               || evidence.EvidenceCategory.StartsWith(EndpointProtectionCategories.Disconnect, StringComparison.OrdinalIgnoreCase)
               || HasDisconnectWording(evidence.Summary)
               || HasDisconnectWording(evidence.RawText);
    }

    private static bool HasDisconnectWording(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        var cleaned = FalseDisconnectContext.Replace(text, " ");
        return DisconnectWordPattern.IsMatch(cleaned);
    }

    private static string ClassifyEvidence(EvidenceRecord evidence)
    {
        if (evidence.Source.Contains("Correlation", StringComparison.OrdinalIgnoreCase))
        {
            return "Корреляция";
        }

        if (evidence.Source.Contains("LNK", StringComparison.OrdinalIgnoreCase)
            || evidence.Source.Contains("JumpList", StringComparison.OrdinalIgnoreCase)
            || evidence.Source.Contains("Recent", StringComparison.OrdinalIgnoreCase)
            || evidence.Source.Contains("Hive", StringComparison.OrdinalIgnoreCase))
        {
            return "Пользовательская активность";
        }

        if (evidence.Source.Contains("Prefetch", StringComparison.OrdinalIgnoreCase)
            || evidence.Source.Contains("Amcache", StringComparison.OrdinalIgnoreCase)
            || evidence.Source.Contains("Shimcache", StringComparison.OrdinalIgnoreCase))
        {
            return "Запуск/исполнение";
        }

        var cleanerAssessment = CleanerEvidenceClassifier.Analyze(evidence);
        if (evidence.EventId is "104" or "1102"
            || cleanerAssessment is not null
            && CleanerToolCatalog.IsTraceRemovalTool(cleanerAssessment.Tool))
        {
            return "Очистка/антифорензика";
        }

        return "Сырой системный артефакт";
    }

    private static string ExplainEvidence(EvidenceRecord evidence)
    {
        if (evidence.Source.Contains("Prefetch", StringComparison.OrdinalIgnoreCase))
        {
            var cleanerAssessment = CleanerEvidenceClassifier.Analyze(evidence);
            return cleanerAssessment is not null
                   && CleanerToolCatalog.IsTraceRemovalTool(cleanerAssessment.Tool)
                ? $"Prefetch подтверждает запуск {cleanerAssessment.Tool}. Сам запуск не доказывает, что очистка была выполнена."
                : "Prefetch: Windows сохранила след запуска программы. Пути к USB/дискам внутри .pf — подсказка об активности, не прямое подключение флешки.";
        }

        if (evidence.Source.Contains("JumpList", StringComparison.OrdinalIgnoreCase))
        {
            return "Jump List в профиле пользователя: недавние пути к файлам или томам — признак работы с USB/съёмным диском.";
        }

        if (evidence.Source.Contains("LNK", StringComparison.OrdinalIgnoreCase)
            || evidence.Source.Contains("Recent", StringComparison.OrdinalIgnoreCase))
        {
            return "Ярлык (LNK) или Recent: пользователь открывал файл/папку — часто с removable-диска или сетевого пути.";
        }

        if (evidence.Source.Contains("MountPoints2", StringComparison.OrdinalIgnoreCase))
        {
            return "MountPoints2: Explorer запомнил точку монтирования тома — след буквы диска или съёмного носителя.";
        }

        if (evidence.Source.Contains("Hive", StringComparison.OrdinalIgnoreCase))
        {
            return "Файл реестра профиля (NTUSER/UsrClass): источник MRU, MountPoints2 и других пользовательских следов.";
        }

        if (evidence.Source.Contains("Amcache", StringComparison.OrdinalIgnoreCase))
        {
            return "Amcache: Windows хранит следы установки/запуска программ — иногда с путями к USB или cleaner-утилитам.";
        }

        if (evidence.Source.Contains("Shimcache", StringComparison.OrdinalIgnoreCase)
            || evidence.Source.Contains("AppCompatCache", StringComparison.OrdinalIgnoreCase))
        {
            return "Shimcache/AppCompatCache: история запуска программ в реестре — вспомогательный след исполнения.";
        }

        if (evidence.Source.Contains("setupapi", StringComparison.OrdinalIgnoreCase))
        {
            return evidence.EvidenceCategory.Contains("Отключение", StringComparison.OrdinalIgnoreCase)
                ? "setupapi.dev.log: Windows зафиксировала удаление или остановку USB-устройства."
                : "setupapi.dev.log: установка драйвера USB — сильный след первого появления устройства в системе.";
        }

        return evidence.EvidenceCategory switch
        {
            "Пользовательская активность" => "След в профиле пользователя: Recent, LNK, Jump Lists, MountPoints2 или MRU.",
            "Запуск/исполнение" => "След запуска программы: Prefetch, Amcache или Shimcache.",
            "Корреляция" => "Автоматическая связь устройства с несколькими источниками доказательств.",
            "Очистка/антифорензика" => "Признак очистки журналов или запуска утилит удаления следов.",
            _ => "Системный forensic-артефакт Windows."
        };
    }
}
