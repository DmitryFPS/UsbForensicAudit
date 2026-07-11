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
        evidence.Source = TextSanitizer.NormalizeDisplay(evidence.Source, 220);
        evidence.EvidenceCategory = TextSanitizer.NormalizeDisplay(evidence.EvidenceCategory, 220);
        evidence.UserExplanation = TextSanitizer.NormalizeDisplay(evidence.UserExplanation, 800);
        evidence.EventId = TextSanitizer.NormalizeDisplay(evidence.EventId, 120);
        evidence.Level = TextSanitizer.NormalizeDisplay(evidence.Level, 120);
        evidence.DeviceHint = TextSanitizer.NormalizeDisplay(evidence.DeviceHint, 500);
        evidence.Summary = TextSanitizer.NormalizeDisplay(evidence.Summary, 800);
        evidence.RawText = TextSanitizer.NormalizeDisplay(evidence.RawText, 4000);
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

        if (timelineMatches.Length == 0 && device.IsCurrentlyConnected)
        {
            timelineMatches = FindRelaxedTimelineMatches(evidence, device);
        }

        var connectionMatches = timelineMatches
            .Where(IsConnectionEvidence)
            .OrderBy(x => x.TimestampUtc)
            .ToArray();

        var disconnectMatches = timelineMatches
            .Where(IsDisconnectEvidence)
            .OrderBy(x => x.TimestampUtc)
            .ToArray();

        if (connectionMatches.Length > 0)
        {
            device.FirstConnectedUtc = connectionMatches.First().TimestampUtc;
            device.LastSeenUtc = timelineMatches.Max(x => x.TimestampUtc);
            device.ConnectionDisplayKind = "ExactEvent";
            device.DateConfidence = "Даты взяты из журнала Windows и setupapi.dev.log.";
        }
        else if (timelineMatches.Length > 0)
        {
            device.LastSeenUtc = timelineMatches.Max(x => x.TimestampUtc);
            device.DateConfidence = "Устройство видно в системе, но точное время первого подключения не найдено.";
        }
        else
        {
            device.DateConfidence = "Windows помнит устройство, но когда его подключали — неизвестно.";
        }

        ApplyLiveConnectionFallback(device, scanStartedUtc);

        if (disconnectMatches.Length > 0)
        {
            device.LastDisconnectedUtc = disconnectMatches.Last().TimestampUtc;
            device.DisconnectDisplayKind = "ExactEvent";
            if (device.IsCurrentlyConnected)
            {
                device.DateConfidence += " Сейчас устройство снова подключено.";
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
            .Where(e => !e.EvidenceCategory.Contains("Очистка", StringComparison.OrdinalIgnoreCase))
            .Where(IsExactDeviceTimelineEvidence)
            .ToArray();
    }

    private static EvidenceRecord[] FindRelaxedTimelineMatches(IReadOnlyList<EvidenceRecord> evidence, UsbDeviceRecord device)
    {
        if (string.IsNullOrWhiteSpace(device.Vid) || string.IsNullOrWhiteSpace(device.Pid))
        {
            return [];
        }

        var vidToken = $"VID_{device.Vid}";
        var pidToken = $"PID_{device.Pid}";
        var compactVidPidToken = $"Vid_{device.Vid}Pid_{device.Pid}";

        return evidence
            .Where(e => (ContainsToken(e, vidToken) && ContainsToken(e, pidToken)) || ContainsToken(e, compactVidPidToken))
            .Where(e => DateDisplay.IsReliable(e.TimestampUtc))
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
                device.LastSeenUtc = Max(device.LastSeenUtc, scanStartedUtc);
            }

            return;
        }

        if (device.RegistryLastWriteUtc.HasValue)
        {
            device.FirstConnectedUtc = device.RegistryLastWriteUtc;
            device.ConnectionDisplayKind = "RegistryActivity";
            device.LastSeenUtc = Max(device.LastSeenUtc, scanStartedUtc);
            device.DateConfidence =
                "Устройство подключено сейчас. Точные журналы Windows недоступны (часто из-за DLP). Дата взята из изменения записи в реестре.";
            return;
        }

        device.FirstConnectedUtc = scanStartedUtc;
        device.ConnectionDisplayKind = "LiveAtScan";
        device.LastSeenUtc = scanStartedUtc;
        device.DateConfidence =
            "Устройство подключено сейчас и обнаружено при сканировании. DLP может скрывать обычные следы Windows.";
    }

    private static DateTimeOffset Max(DateTimeOffset? current, DateTimeOffset candidate)
    {
        return current.HasValue ? (current.Value > candidate ? current.Value : candidate) : candidate;
    }

    private static IEnumerable<string> BuildTokens(UsbDeviceRecord device)
    {
        if (!string.IsNullOrWhiteSpace(device.Vid) && !string.IsNullOrWhiteSpace(device.Pid))
        {
            yield return $"VID_{device.Vid}";
            yield return $"PID_{device.Pid}";
            yield return $"VID_{device.Vid}&PID_{device.Pid}";
            yield return $"Vid_{device.Vid}Pid_{device.Pid}";
            yield return $"{device.Vid}:{device.Pid}";
        }

        foreach (var field in new[]
                 {
                     device.FriendlyName,
                     device.Product,
                     device.Manufacturer,
                     device.Serial,
                     device.DeviceInstanceId
                 })
        {
            foreach (var token in CompactVidPidParser.BuildMatchTokens(field))
            {
                yield return token;
            }
        }

        foreach (var token in new[]
                 {
                     device.Serial,
                     device.ContainerId,
                     device.ParentIdPrefix,
                     device.DeviceInstanceId
                 })
        {
            var cleaned = NormalizeStrongToken(token);
            if (IsStrongToken(cleaned))
            {
                yield return cleaned;
            }
        }
    }

    private static bool ContainsToken(EvidenceRecord evidence, string token)
    {
        return evidence.DeviceHint.Contains(token, StringComparison.OrdinalIgnoreCase)
               || evidence.Summary.Contains(token, StringComparison.OrdinalIgnoreCase)
               || evidence.RawText.Contains(token, StringComparison.OrdinalIgnoreCase);
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

    private static bool IsDisconnectEvidence(EvidenceRecord evidence)
    {
        return evidence.EvidenceCategory.Contains("Отключение", StringComparison.OrdinalIgnoreCase)
               || evidence.EvidenceCategory.StartsWith(EndpointProtectionCategories.Disconnect, StringComparison.OrdinalIgnoreCase)
               || evidence.Summary.Contains("disconnect", StringComparison.OrdinalIgnoreCase)
               || evidence.Summary.Contains("removed", StringComparison.OrdinalIgnoreCase)
               || evidence.Summary.Contains("removal", StringComparison.OrdinalIgnoreCase)
               || evidence.Summary.Contains("uninstall", StringComparison.OrdinalIgnoreCase)
               || evidence.Summary.Contains("отключ", StringComparison.OrdinalIgnoreCase)
               || evidence.Summary.Contains("удален", StringComparison.OrdinalIgnoreCase)
               || evidence.RawText.Contains("disconnect", StringComparison.OrdinalIgnoreCase)
               || evidence.RawText.Contains("removed", StringComparison.OrdinalIgnoreCase)
               || evidence.RawText.Contains("отключ", StringComparison.OrdinalIgnoreCase)
               || evidence.RawText.Contains("удален", StringComparison.OrdinalIgnoreCase);
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

        if (evidence.EventId is "104" or "1102" or "CLEANER_HINT")
        {
            return "Очистка/антифорензика";
        }

        return "Сырой системный артефакт";
    }

    private static string NormalizeStrongToken(string value)
    {
        return value.Trim().Trim('{', '}').Replace(@"\\", @"\");
    }

    private static bool IsStrongToken(string value)
    {
        if (value.Length < 8)
        {
            return false;
        }

        if (value.Equals("00000000", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Windows", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Volume", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Generic", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return value.Contains('\\')
               || value.Contains('&')
               || value.Contains('-')
               || value.Any(char.IsDigit);
    }

    private static string ExplainEvidence(EvidenceRecord evidence)
    {
        if (evidence.Source.Contains("Prefetch", StringComparison.OrdinalIgnoreCase))
        {
            return evidence.EventId == "CLEANER_HINT"
                ? "Prefetch: Windows запускала утилиту очистки USB-следов — возможный признак anti-forensics."
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
