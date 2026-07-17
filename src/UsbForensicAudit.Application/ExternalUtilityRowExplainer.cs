using System.Globalization;
using System.Text;

namespace UsbForensicAudit;

public static class ExternalUtilityRowExplainer
{
    public static ExternalUtilityRowAssessment Assess(ExternalUtilityRow row, AuditResult? audit) =>
        Assess(row, audit, null, null, null);

    public static ExternalUtilityRowAssessment Assess(
        ExternalUtilityRow row,
        AuditResult? audit,
        IReadOnlyList<ExternalUtilitySourceHit>? procmonHits,
        string? procmonSessionDirectory,
        string? procmonSummaryForReport,
        IExternalUtilityRegistryTracer? registryTracer = null)
    {
        var identifier = ExternalUtilityIdentifierParser.Parse(row);
        var isOtherTraces = ExternalUtilitySectionCatalog.IsOtherTracesSection(row.SectionTitle);
        var isUsbDetector = row.UtilityName.Contains("USBDetector", StringComparison.OrdinalIgnoreCase);
        var installText = ExternalUtilityColumnNormalizer.FindConnectionDate(row.Values)
                          ?? FindValue(row, "Установка", "Installation", "First connection", "Подключение", "Дата", "Первое подключение", "Модификация");
        var matches = audit is null ? [] : FindMatchingDevices(row, audit, identifier).Take(5).ToArray();
        var hasEpochDate = LooksLikeUnixEpoch(installText);
        var beforeOsInstall = audit?.OsInstalledAtUtc is not null
                              && TryParseRowDate(installText, out var rowDate)
                              && rowDate < audit.OsInstalledAtUtc.Value;

        var level = ResolveVerdictLevel(row, isOtherTraces, identifier, matches.Length, hasEpochDate, beforeOsInstall);
        var origin = ResolveProbableOrigin(row, identifier, isOtherTraces, matches);
        var auditSummary = ResolveAuditMatchSummary(matches, audit, isOtherTraces);
        var baseHits = ExternalUtilitySourceCorrelator.Correlate(identifier, audit, registryTracer);
        var sourceHits = procmonHits is { Count: > 0 }
            ? ExternalUtilitySourceCorrelator.MergeProcmonHits(baseHits, procmonHits)
            : baseHits;
        var hasProcmon = sourceHits.Any(x => x.IsProcmonEvidence && x.Found);
        var topProcmonHit = sourceHits.FirstOrDefault(x => x.IsProcmonEvidence && x.Found);
        var sourceChecksText = ExternalUtilitySourceCorrelator.FormatSourceChecks(sourceHits, isUsbDetector, isOtherTraces);
        var reportConclusionProcmon = hasProcmon
            ? procmonSummaryForReport ?? (topProcmonHit is null
                ? null
                : ProcmonReportBuilder.BuildSummary(row, identifier, sourceHits.Where(x => x.IsProcmonEvidence).ToArray()))
            : null;
        origin = ResolveProbableOriginWithProcmon(topProcmonHit, origin);
        var reportConclusionRow = BuildReportConclusionRow(
            row, audit, level, identifier, origin, auditSummary, matches, isOtherTraces, reportConclusionProcmon);
        var reportConclusionCase = BuildReportConclusionCase(row, audit, level, identifier, matches, isOtherTraces, hasProcmon);
        var verdictTitle = VerdictTitle(level, row, isOtherTraces, identifier, hasProcmon, topProcmonHit);
        var detectorNote = ResolveUsbDetectorNote(row, identifier, isOtherTraces, hasEpochDate, beforeOsInstall, matches.Length, hasProcmon);

        return new ExternalUtilityRowAssessment
        {
            Level = level,
            VerdictTitle = verdictTitle,
            ProbableOrigin = origin,
            UsbDetectorNote = detectorNote,
            AuditMatchSummary = auditSummary,
            ReportConclusionRow = reportConclusionRow,
            ReportConclusionCase = reportConclusionCase,
            ReportConclusionProcmon = reportConclusionProcmon,
            ProcmonSessionDirectory = procmonSessionDirectory,
            Identifier = identifier,
            SourceHits = sourceHits,
            SourceChecksText = sourceChecksText,
            FullExplanation = Explain(
                row,
                audit,
                identifier,
                verdictTitle,
                origin,
                detectorNote,
                auditSummary,
                reportConclusionRow,
                reportConclusionCase,
                reportConclusionProcmon,
                sourceChecksText,
                matches,
                installText,
                hasEpochDate,
                beforeOsInstall,
                isOtherTraces)
        };
    }

    public static string Explain(ExternalUtilityRow row, AuditResult? audit) =>
        Assess(row, audit).FullExplanation;

    public static string ShortVerdict(ExternalUtilityRow row, AuditResult? audit) =>
        Assess(row, audit).VerdictTitle;

    private static string Explain(
        ExternalUtilityRow row,
        AuditResult? audit,
        ExternalUtilityIdentifierInfo identifier,
        string verdictTitle,
        string origin,
        string detectorNote,
        string auditSummary,
        string reportConclusionRow,
        string reportConclusionCase,
        string? reportConclusionProcmon,
        string sourceChecksText,
        IReadOnlyList<UsbDeviceRecord> matches,
        string installText,
        bool hasEpochDate,
        bool beforeOsInstall,
        bool isOtherTraces)
    {
        var builder = new StringBuilder();

        builder.Append(row.UtilityName).Append(" · ").AppendLine(row.SectionTitle);
        builder.Append("Запись: ").AppendLine(row.PrimaryText);
        builder.Append("Вердикт: ").AppendLine(verdictTitle);
        builder.AppendLine();

        builder.AppendLine("ФОРМУЛИРОВКА ПО СТРОКЕ (для отчёта):");
        builder.AppendLine(reportConclusionRow);
        builder.AppendLine();

        if (!string.IsNullOrWhiteSpace(reportConclusionProcmon))
        {
            builder.AppendLine("PROCMON (ЖЁСТКОЕ ДОКАЗАТЕЛЬСТВО — ЧТЕНИЕ РЕЕСТРА УТИЛИТОЙ):");
            builder.AppendLine(reportConclusionProcmon);
            builder.AppendLine();
        }

        builder.AppendLine("ФОРМУЛИРОВКА ПО ДЕЛУ (общий вывод по USB на ПК):");
        builder.AppendLine(reportConclusionCase);
        builder.AppendLine();

        builder.AppendLine(sourceChecksText);
        builder.AppendLine();

        builder.AppendLine("Кратко:");
        builder.Append("• Откуда строка: ").AppendLine(origin);
        builder.Append("• Замечание: ").AppendLine(detectorNote);
        builder.Append("• Аудит: ").AppendLine(auditSummary);

        if (identifier.HasVid)
        {
            builder.Append("• VID/PID: ")
                .Append(identifier.VidPidText)
                .Append(" · ")
                .AppendLine(identifier.VendorProductText);
        }

        if (hasEpochDate)
        {
            builder.AppendLine("• Дата 01.01.1970 — FILETIME=0 в реестре, не реальное подключение.");
        }

        if (beforeOsInstall && audit?.OsInstalledAtUtc is not null)
        {
            builder.Append("• Дата в утилите (")
                .Append(installText)
                .Append(") раньше установки Windows (")
                .Append(audit.OsInstalledAtText)
                .AppendLine(") — ненадёжна.");
        }

        if (matches.Count > 0)
        {
            builder.AppendLine("• Совпадения в аудите:");
            foreach (var device in matches)
            {
                builder.Append("  — ")
                    .Append(device.DisplayName)
                    .Append(": ")
                    .AppendLine(ToRegistryPath(device));
            }
        }

        if (isOtherTraces)
        {
            builder.AppendLine();
            builder.AppendLine("Раздел «Другие следы»: косвенные ключи Windows; одна строка ≠ доказательство флешки.");
        }

        if (row.UtilityName.Contains("Oblivion", StringComparison.OrdinalIgnoreCase))
        {
            builder.AppendLine("USB Oblivion удаляет следы — см. вкладку «Следы очистки».");
        }

        return builder.ToString().TrimEnd();
    }

    private static string BuildReportConclusionRow(
        ExternalUtilityRow row,
        AuditResult? audit,
        ExternalUtilityVerdictLevel level,
        ExternalUtilityIdentifierInfo identifier,
        string origin,
        string auditSummary,
        IReadOnlyList<UsbDeviceRecord> matches,
        bool isOtherTraces,
        string? reportConclusionProcmon)
    {
        var deviceName = identifier.VendorLookup.DeviceDescription;
        var idText = identifier.HasFullPair
            ? $"VID {identifier.Vid} / PID {identifier.Pid}"
            : identifier.HasVid
                ? $"VID {identifier.Vid}"
                : row.PrimaryText;

        if (!string.IsNullOrWhiteSpace(deviceName))
        {
            idText = $"{idText} ({deviceName})";
        }

        var utilityLabel = row.UtilityName.Contains("USBDeview", StringComparison.OrdinalIgnoreCase) ? "USBDeview" : "USBDetector";
        var baseConclusion = level switch
        {
            ExternalUtilityVerdictLevel.Confirmed when matches.Count > 0 =>
                $"{utilityLabel}, строка «{row.PrimaryText}»: {idText}. Подтверждено аудитом — {matches[0].DisplayName}, путь {ToRegistryPath(matches[0])}.",

            ExternalUtilityVerdictLevel.Probable when matches.Count > 0 =>
                $"{utilityLabel}, «Другие следы»: {idText}. В аудите есть {matches[0].DisplayName}, но строка из косвенного раздела — дату в утилите проверять отдельно.",

            ExternalUtilityVerdictLevel.Virtual =>
                $"{utilityLabel}, «Другие следы»: {idText}. Виртуальное USB VMware — не физический накопитель; к подключению флешки не относится.",

            ExternalUtilityVerdictLevel.DateArtifact =>
                $"{utilityLabel}: {idText}. Дата в утилите ненадёжна (1970 или до установки Windows). {auditSummary}",

            ExternalUtilityVerdictLevel.Indirect =>
                $"{utilityLabel}, «Другие следы»: {idText}. {origin} Эта строка — косвенный след, не доказательство подключения USB-накопителя.",

            ExternalUtilityVerdictLevel.NotFound =>
                $"{utilityLabel} ({row.SectionTitle}): {idText}. В аудите не найдено. {auditSummary}",

            _ =>
                $"{utilityLabel}: {idText}. Требуется ручная сверка с реестром и аудитом."
        };

        if (string.IsNullOrWhiteSpace(reportConclusionProcmon))
        {
            return baseConclusion;
        }

        return $"{baseConclusion} Procmon подтвердил чтение реестра утилитой — см. блок Procmon ниже.";
    }

    private static string BuildReportConclusionCase(
        ExternalUtilityRow row,
        AuditResult? audit,
        ExternalUtilityVerdictLevel level,
        ExternalUtilityIdentifierInfo identifier,
        IReadOnlyList<UsbDeviceRecord> matches,
        bool isOtherTraces,
        bool hasProcmon)
    {
        if (audit is null)
        {
            return "По делу: полное сканирование не выполнялось — общий вывод по USB на этом ПК пока недоступен.";
        }

        var realUsbCount = audit.Devices.Count(d =>
            d.Source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
            || (d.Source.Contains("Registry: USB", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(d.Vid)));

        var storageCount = audit.Devices.Count(d => d.Source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase));

        if (hasProcmon && isOtherTraces)
        {
            return $"По делу: на ПК {realUsbCount} USB-записей реестра, {storageCount} USBSTOR. Procmon зафиксировал, какую ветку реестра читала утилита для этой строки — это доказательство источника строки, но не автоматически физической флешки.";
        }

        if (level is ExternalUtilityVerdictLevel.Virtual)
        {
            return $"По делу: на ПК в аудите {realUsbCount} USB-записей реестра, {storageCount} накопителей USBSTOR. Строка VID {identifier.Vid} — виртуальное устройство VMware, не свидетельствует о флешках.";
        }

        if (level is ExternalUtilityVerdictLevel.Confirmed or ExternalUtilityVerdictLevel.Probable && matches.Count > 0)
        {
            return $"По делу: на ПК зафиксировано {realUsbCount} USB-записей, {storageCount} USBSTOR. Строка утилиты согласуется с аудитом ({matches[0].DisplayName}) — устройство реально присутствовало в системе.";
        }

        if (isOtherTraces && matches.Count == 0)
        {
            return $"По делу: на ПК {realUsbCount} USB-записей реестра, {storageCount} USBSTOR. Отсутствие совпадения по одной строке «Других следов» не означает «USB не было» — только что эта запись не подтверждена прямым следом.";
        }

        if (level is ExternalUtilityVerdictLevel.NotFound)
        {
            return $"По делу: на ПК {realUsbCount} USB-записей, {storageCount} USBSTOR. Строка утилиты не подтверждена аудитом — возможны удаление следов, ошибка утилиты или устройство только в её локальной истории.";
        }

        return $"По делу: на ПК {realUsbCount} USB-записей реестра, {storageCount} накопителей USBSTOR. Оценивайте строку утилиты вместе с вкладками «USB устройства» и «Доказательства».";
    }

    private static string ToRegistryPath(UsbDeviceRecord device)
    {
        if (device.DeviceInstanceId.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase)
            || device.DeviceInstanceId.StartsWith(@"HKU\", StringComparison.OrdinalIgnoreCase))
        {
            return device.DeviceInstanceId;
        }

        if (device.Source.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase))
        {
            return @"HKLM\SYSTEM\MountedDevices";
        }

        if (device.DeviceInstanceId.Contains('\\'))
        {
            return $@"HKLM\SYSTEM\CurrentControlSet\Enum\{device.DeviceInstanceId}";
        }

        return device.DeviceInstanceId;
    }

    private static ExternalUtilityVerdictLevel ResolveVerdictLevel(
        ExternalUtilityRow row,
        bool isOtherTraces,
        ExternalUtilityIdentifierInfo identifier,
        int matchCount,
        bool hasEpochDate,
        bool beforeOsInstall)
    {
        if (matchCount > 0 && !isOtherTraces)
        {
            return ExternalUtilityVerdictLevel.Confirmed;
        }

        if (matchCount > 0 && isOtherTraces)
        {
            return ExternalUtilityVerdictLevel.Probable;
        }

        if (identifier.Vid?.Equals("0E0F", StringComparison.OrdinalIgnoreCase) == true
            || (identifier.VendorLookup.VendorName?.Contains("VMware", StringComparison.OrdinalIgnoreCase) == true && isOtherTraces))
        {
            return ExternalUtilityVerdictLevel.Virtual;
        }

        if (hasEpochDate || beforeOsInstall)
        {
            return ExternalUtilityVerdictLevel.DateArtifact;
        }

        if (isOtherTraces)
        {
            return ExternalUtilityVerdictLevel.Indirect;
        }

        if (matchCount == 0)
        {
            return ExternalUtilityVerdictLevel.NotFound;
        }

        return ExternalUtilityVerdictLevel.Unknown;
    }

    private static string ResolveProbableOriginWithProcmon(
        ExternalUtilitySourceHit? topProcmonHit,
        string fallbackOrigin)
    {
        if (topProcmonHit is null || !topProcmonHit.Found)
        {
            return fallbackOrigin;
        }

        var kind = topProcmonHit.ResultText.Contains("прямой", StringComparison.OrdinalIgnoreCase)
            ? "прямой ключ реестра USB"
            : topProcmonHit.ResultText.Contains("косвен", StringComparison.OrdinalIgnoreCase)
                ? "косвенный ключ Windows"
                : "запись реестра";

        return $"Procmon: утилита выполнила {topProcmonHit.Operation} → {kind} «{topProcmonHit.RegistryPath}».";
    }

    private static string VerdictTitle(
        ExternalUtilityVerdictLevel level,
        ExternalUtilityRow row,
        bool isOtherTraces,
        ExternalUtilityIdentifierInfo identifier,
        bool hasProcmon,
        ExternalUtilitySourceHit? topProcmonHit)
    {
        var isUsbDeview = row.UtilityName.Contains("USBDeview", StringComparison.OrdinalIgnoreCase)
                          || row.SectionTitle.Contains("USBDeview", StringComparison.OrdinalIgnoreCase);

        if (hasProcmon && topProcmonHit is not null)
        {
            var procmonKind = topProcmonHit.ResultText.Contains("прямой", StringComparison.OrdinalIgnoreCase)
                ? "прямой ключ реестра"
                : "косвенный ключ Windows";
            return isOtherTraces
                ? $"Procmon — источник строки доказан ({procmonKind})"
                : $"Procmon — утилита читала {procmonKind}";
        }

        return level switch
        {
            ExternalUtilityVerdictLevel.Confirmed when isUsbDeview =>
                "Подтверждено — VID/PID совпадает с вкладкой «USB устройства»",
            ExternalUtilityVerdictLevel.Confirmed =>
                "Подтверждено — устройство есть в нашем аудите и в основном списке реестра",
            ExternalUtilityVerdictLevel.Probable => "Вероятно реальное USB — есть совпадение в нашем аудите, но строка из «Других следов»",
            ExternalUtilityVerdictLevel.Indirect => isOtherTraces
                ? "Косвенный след — не доказывает физическое подключение флешки"
                : "Косвенный след — нужна сверка с журналами",
            ExternalUtilityVerdictLevel.Virtual => "Виртуальное устройство (VMware) — не физическая флешка",
            ExternalUtilityVerdictLevel.DateArtifact => "Артефакт даты — колонка даты в утилите ненадёжна",
            ExternalUtilityVerdictLevel.NotFound when isUsbDeview && !identifier.HasVid =>
                "Не подтверждено — не удалось прочитать VID/PID из строки USBDeview",
            ExternalUtilityVerdictLevel.NotFound when isUsbDeview =>
                "Не подтверждено — VID/PID из USBDeview не найдены во вкладке «USB устройства»",
            ExternalUtilityVerdictLevel.NotFound =>
                "Не подтверждено нашим аудитом — только показание утилиты",
            _ => "Требуется ручная проверка"
        };
    }

    private static string ResolveProbableOrigin(
        ExternalUtilityRow row,
        ExternalUtilityIdentifierInfo identifier,
        bool isOtherTraces,
        IReadOnlyList<UsbDeviceRecord> matches)
    {
        if (identifier.Vid?.Equals("0E0F", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "VMware (VID 0E0F) — виртуальный USB.";
        }

        if (identifier.VendorLookup.HasVendor && isOtherTraces)
        {
            return $"Косвенный ключ Windows, код {identifier.Vid} ({identifier.VendorLookup.VendorName}).";
        }

        if (matches.Count > 0)
        {
            return $"Подтверждение в аудите: {ToRegistryPath(matches[0])}.";
        }

        if (isOtherTraces)
        {
            var text = string.Join(' ', row.Values.Values).ToUpperInvariant();
            if (text.Contains("MOUNTED") || text.Contains("MOUNT"))
            {
                return "Вероятно HKLM\\SYSTEM\\MountedDevices.";
            }

            if (text.Contains("MRU") || text.Contains("RECENT"))
            {
                return "Вероятно MRU/Recent пользователя.";
            }

            return "Косвенный ключ (MRU, MountedDevices, MountPoints2) — типичный источник «Других следов» USBDetector.";
        }

        return "Enum\\USB / USBSTOR или список USBDeview.";
    }

    private static string ResolveUsbDetectorNote(
        ExternalUtilityRow row,
        ExternalUtilityIdentifierInfo identifier,
        bool isOtherTraces,
        bool hasEpochDate,
        bool beforeOsInstall,
        int matchCount,
        bool hasProcmon)
    {
        var isUsbDeview = row.UtilityName.Contains("USBDeview", StringComparison.OrdinalIgnoreCase);

        if (hasProcmon)
        {
            return "Procmon зафиксировал чтение реестра процессом утилиты — это жёсткое доказательство источника строки.";
        }

        if (isUsbDeview && matchCount > 0)
        {
            return "USBDeview и аудит совпали по VID/PID.";
        }

        if (isUsbDeview && !identifier.HasVid)
        {
            return "Не найдены колонки Vendor ID / Product ID.";
        }

        if (isUsbDeview && identifier.HasVid && matchCount == 0)
        {
            return $"VID/PID {identifier.VidPidText} в USBDeview, в аудите нет — след мог быть удалён.";
        }

        if (!string.IsNullOrWhiteSpace(identifier.ParseNote)
            && identifier.ParseMethod.Contains("Обрезан", StringComparison.OrdinalIgnoreCase))
        {
            return identifier.ParseNote;
        }

        if (hasEpochDate)
        {
            return "Дата 01.01.1970 — FILETIME=0, не реальное подключение.";
        }

        if (beforeOsInstall)
        {
            return "Дата раньше установки Windows — косвенный источник USBDetector.";
        }

        if (isOtherTraces && matchCount == 0 && identifier.HasVid && !identifier.HasFullPair)
        {
            return "Неполный VID без PID — так отображает USBDetector.";
        }

        if (isOtherTraces && matchCount == 0)
        {
            return "Только «Другие следы», без совпадения в аудите — косвенная запись.";
        }

        if (isOtherTraces)
        {
            return "Раздел «Другие следы» шире основного списка реестра.";
        }

        return "Основной список ближе к Enum\\USB/USBSTOR.";
    }

    private static string ResolveAuditMatchSummary(
        IReadOnlyList<UsbDeviceRecord> matches,
        AuditResult? audit,
        bool isOtherTraces)
    {
        if (audit is null)
        {
            return "Сканирование не выполнялось.";
        }

        if (matches.Count == 0)
        {
            return isOtherTraces
                ? "Совпадений нет — для «Других следов» это часто нормально."
                : "Совпадений нет — см. setupapi и «Доказательства».";
        }

        return $"Совпадений: {matches.Count}.";
    }

    private static IEnumerable<UsbDeviceRecord> FindMatchingDevices(
        ExternalUtilityRow row,
        AuditResult audit,
        ExternalUtilityIdentifierInfo identifier)
    {
        var serial = FindValue(row, "Serial", "Серийный номер", "UID");
        var name = FindValue(row, "Модель", "Model", "Производитель", "Manufacturer", "Носитель информации", "UID");

        return audit.Devices.Where(device =>
        {
            if (!string.IsNullOrWhiteSpace(identifier.Vid)
                && !string.IsNullOrWhiteSpace(identifier.Pid)
                && device.Vid.Equals(identifier.Vid, StringComparison.OrdinalIgnoreCase)
                && device.Pid.Equals(identifier.Pid, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!string.IsNullOrWhiteSpace(identifier.Vid)
                && string.IsNullOrWhiteSpace(identifier.Pid)
                && device.Vid.Equals(identifier.Vid, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!string.IsNullOrWhiteSpace(name))
            {
                if (device.DisplayName.Contains(name, StringComparison.OrdinalIgnoreCase)
                    || device.DeviceInstanceId.Contains(name, StringComparison.OrdinalIgnoreCase)
                    || device.ManufacturerText.Contains(name, StringComparison.OrdinalIgnoreCase)
                    || device.ModelText.Contains(name, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            if (!string.IsNullOrWhiteSpace(serial)
                && serial.Length > 6
                && (device.Serial.Contains(serial, StringComparison.OrdinalIgnoreCase)
                    || device.DeviceInstanceId.Contains(serial, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            return false;
        });
    }

    private static string FindValue(ExternalUtilityRow row, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (row.Values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return "";
    }

    private static bool LooksLikeUnixEpoch(string? text) =>
        !string.IsNullOrWhiteSpace(text) && text.Contains("1970", StringComparison.Ordinal);

    private static bool TryParseRowDate(string? text, out DateTimeOffset date)
    {
        date = default;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var formats = new[]
        {
            "dd.MM.yyyy HH:mm",
            "dd.MM.yyyy H:mm",
            "dd.MM.yyyy HH:mm:ss",
            "dd.MM.yyyy"
        };

        if (DateTime.TryParseExact(text.Trim(), formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsed))
        {
            date = new DateTimeOffset(parsed);
            return true;
        }

        return DateTimeOffset.TryParse(text, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out date);
    }
}
