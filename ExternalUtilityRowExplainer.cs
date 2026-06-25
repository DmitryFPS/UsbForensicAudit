using System.Globalization;
using System.Text;

namespace UsbForensicAudit;

public static class ExternalUtilityRowExplainer
{
    public static ExternalUtilityRowAssessment Assess(ExternalUtilityRow row, AuditResult? audit)
    {
        var identifier = ExternalUtilityIdentifierParser.Parse(row);
        var isOtherTraces = ExternalUtilitySectionCatalog.IsOtherTracesSection(row.SectionTitle);
        var vid = identifier.Vid;
        var pid = identifier.Pid;
        var installText = ExternalUtilityColumnNormalizer.FindConnectionDate(row.Values)
                          ?? FindValue(row, "Установка", "Installation", "First connection", "Подключение", "Дата", "Первое подключение", "Модификация");
        var matches = audit is null ? [] : FindMatchingDevices(row, audit, identifier).Take(5).ToArray();
        var hasEpochDate = LooksLikeUnixEpoch(installText);
        var beforeOsInstall = audit?.OsInstalledAtUtc is not null
                              && TryParseRowDate(installText, out var rowDate)
                              && rowDate < audit.OsInstalledAtUtc.Value;

        var level = ResolveVerdictLevel(row, isOtherTraces, identifier, matches.Length, hasEpochDate, beforeOsInstall);
        var origin = ResolveProbableOrigin(row, identifier, isOtherTraces, matches);
        var detectorNote = ResolveUsbDetectorNote(row, identifier, isOtherTraces, hasEpochDate, beforeOsInstall, matches.Length);
        var auditSummary = ResolveAuditMatchSummary(matches, audit, isOtherTraces);
        var reportConclusion = BuildReportConclusion(row, audit, level, identifier, origin, auditSummary, matches);

        return new ExternalUtilityRowAssessment
        {
            Level = level,
            VerdictTitle = VerdictTitle(level, row, isOtherTraces, identifier),
            ProbableOrigin = origin,
            UsbDetectorNote = detectorNote,
            AuditMatchSummary = auditSummary,
            ReportConclusion = reportConclusion,
            Identifier = identifier,
            FullExplanation = Explain(row, audit, identifier, level, origin, detectorNote, auditSummary, reportConclusion, matches)
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
        ExternalUtilityVerdictLevel level,
        string origin,
        string detectorNote,
        string auditSummary,
        string reportConclusion,
        IReadOnlyList<UsbDeviceRecord> matches)
    {
        var builder = new StringBuilder();
        var sectionInfo = ExternalUtilitySectionCatalog.GetInfo(row.SectionTitle);
        var isOtherTraces = ExternalUtilitySectionCatalog.IsOtherTracesSection(row.SectionTitle);

        builder.AppendLine($"Утилита: {row.UtilityName}");
        builder.AppendLine($"Раздел: {row.SectionTitle}");
        builder.AppendLine($"Запись: {row.PrimaryText}");
        builder.AppendLine();
        builder.AppendLine("ФОРМУЛИРОВКА ДЛЯ ОТЧЁТА:");
        builder.AppendLine(reportConclusion);
        builder.AppendLine();
        builder.AppendLine($"Вердикт: {VerdictTitle(level, row, isOtherTraces, identifier)}");
        builder.AppendLine($"Откуда, скорее всего: {origin}");
        builder.AppendLine($"Замечание по USBDetector: {detectorNote}");
        builder.AppendLine($"Наш аудит: {auditSummary}");

        AppendIdentifierBlock(builder, identifier);

        if (isOtherTraces)
        {
            builder.AppendLine();
            builder.AppendLine("Что означает раздел «Другие следы подключения устройств»:");
            builder.AppendLine("• Это не список «кто точно подключал флешку», а сбор косвенных записей Windows.");
            builder.AppendLine("• USBDetector смешивает MRU, MountedDevices, виртуальные USB (VMware) и старые ключи.");
            builder.AppendLine("• Дата «первого подключения» здесь часто вычислена ошибочно — особенно 01.01.1970 или дата до установки Windows.");
            builder.AppendLine("• Колонки могут быть обрезаны: вместо VID_0E0F&PID_0003 видно только «0E0F» — это отображение USBDetector, не ошибка нашего считывания.");
            builder.AppendLine();
            builder.AppendLine("Типичные источники таких строк:");
            builder.AppendLine($"• {sectionInfo.TypicalSources}");
        }
        else if (row.SectionTitle.Contains("Основной список", StringComparison.OrdinalIgnoreCase))
        {
            builder.AppendLine();
            builder.AppendLine("Основной список (реестр):");
            builder.AppendLine("• Запись из Enum\\USB / USBSTOR — обычно это реальный след установки драйвера USB-устройства.");
            builder.AppendLine("• Всё равно сверяйте даты с нашим аудитом и setupapi.dev.log.");
        }

        var installText = ExternalUtilityColumnNormalizer.FindConnectionDate(row.Values)
                          ?? FindValue(row, "Установка", "Installation", "First connection", "Подключение", "Дата", "Первое подключение", "Модификация");
        if (LooksLikeUnixEpoch(installText))
        {
            builder.AppendLine();
            builder.AppendLine("Почему дата «01.01.1970»:");
            builder.AppendLine("• В реестре нет реальной даты установки (FILETIME = 0), USBDetector подставляет 01.01.1970.");
            builder.AppendLine("• Это не подключение в 1970 году — игнорируйте эту колонку, смотрите «Модификация» и наш аудит.");
        }

        if (audit is not null)
        {
            builder.AppendLine();
            builder.AppendLine("Сопоставление с нашим аудитом:");
            builder.AppendLine($"• Установка Windows: {audit.OsInstalledAtText}");

            if (matches.Count == 0)
            {
                builder.AppendLine("• В нашем списке USB-устройств прямого совпадения нет.");
                if (isOtherTraces)
                {
                    builder.AppendLine("• Для «Других следов» это нормально: запись может жить только в косвенном источнике USBDetector.");
                }
            }
            else
            {
                foreach (var device in matches)
                {
                    builder.AppendLine($"• Совпадение: {device.DisplayName} ({device.CategoryText})");
                    builder.AppendLine($"  Источник у нас: {device.SourceText}");
                    builder.AppendLine($"  Подключение: {device.FirstConnectedText}; активность: {device.LastSeenText}");
                    builder.AppendLine($"  Достоверность дат: {device.DateConfidenceText}");
                }
            }

            if (TryParseRowDate(installText, out var rowDate)
                && audit.OsInstalledAtUtc is not null
                && rowDate < audit.OsInstalledAtUtc.Value)
            {
                builder.AppendLine();
                builder.AppendLine("Дата в утилите раньше установки Windows:");
                builder.AppendLine("• Часто это не реальное подключение до переустановки.");
                builder.AppendLine("• Возможные причины: перенос профиля, MRU, MountedDevices, ошибка USBDetector, виртуальное устройство.");
            }
        }
        else
        {
            builder.AppendLine();
            builder.AppendLine("Выполните полное сканирование — тогда появится сопоставление с реестром, журналами и хронологией.");
        }

        if (row.UtilityName.Contains("Oblivion", StringComparison.OrdinalIgnoreCase))
        {
            builder.AppendLine();
            builder.AppendLine("USB Oblivion удаляет следы из реестра. Запуск виден в Prefetch; факт удаления — на вкладке «Следы очистки».");
        }

        return builder.ToString().TrimEnd();
    }

    private static void AppendIdentifierBlock(StringBuilder builder, ExternalUtilityIdentifierInfo identifier)
    {
        builder.AppendLine();
        builder.AppendLine("Идентификатор USB (разбор):");
        builder.AppendLine($"• Способ: {identifier.ParseMethod}");

        if (identifier.HasVid)
        {
            builder.AppendLine($"• VID: {identifier.Vid}");
            if (identifier.VendorLookup.HasVendor)
            {
                builder.AppendLine($"• Производитель (база USB ID): {identifier.VendorLookup.VendorName}");
            }
        }

        if (identifier.HasFullPair)
        {
            builder.AppendLine($"• PID: {identifier.Pid}");
            if (identifier.VendorLookup.HasProduct)
            {
                builder.AppendLine($"• Модель (база USB ID): {identifier.VendorLookup.ProductName}");
            }
        }
        else if (identifier.HasVid)
        {
            builder.AppendLine("• PID: не указан в строке USBDetector (идентификатор неполный).");
        }

        if (!string.IsNullOrWhiteSpace(identifier.ParseNote))
        {
            builder.AppendLine($"• Примечание: {identifier.ParseNote}");
        }
    }

    private static string BuildReportConclusion(
        ExternalUtilityRow row,
        AuditResult? audit,
        ExternalUtilityVerdictLevel level,
        ExternalUtilityIdentifierInfo identifier,
        string origin,
        string auditSummary,
        IReadOnlyList<UsbDeviceRecord> matches)
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

        return level switch
        {
            ExternalUtilityVerdictLevel.Confirmed when matches.Count > 0 =>
                $"USBDetector ({row.SectionTitle}): {idText}. " +
                $"Подтверждено полным аудитом — {matches[0].DisplayName}, источник {matches[0].SourceText}. " +
                $"Это реальный след USB-устройства в системе.",

            ExternalUtilityVerdictLevel.Probable when matches.Count > 0 =>
                $"USBDetector («Другие следы»): {idText}. " +
                $"В полном аудите найдено совпадение ({matches[0].DisplayName}), но строка из косвенного раздела USBDetector. " +
                $"Устройство вероятно подключалось; дату «первого подключения» в USBDetector проверять отдельно.",

            ExternalUtilityVerdictLevel.Virtual =>
                $"USBDetector («Другие следы»): запись {row.PrimaryText} → {idText}. " +
                $"Это виртуальное USB VMware, не физический накопитель. " +
                $"Полный аудит USB-накопителей совпадений не даёт — к подключению флешки не относится.",

            ExternalUtilityVerdictLevel.DateArtifact =>
                $"USBDetector: {idText}. Дата в утилите ненадёжна (01.01.1970 или раньше установки Windows). " +
                $"{auditSummary} След трактовать только после сверки с реестром и setupapi.dev.log.",

            ExternalUtilityVerdictLevel.Indirect =>
                $"USBDetector («Другие следы»): {idText}. " +
                $"{origin} Полный аудит совпадений не нашёл — это косвенный след Windows, не доказательство подключения USB-накопителя.",

            ExternalUtilityVerdictLevel.NotFound =>
                $"USBDetector ({row.SectionTitle}): {idText}. " +
                $"В полном аудите устройство не найдено. {auditSummary}",

            _ =>
                $"USBDetector: {idText}. Требуется ручная сверка с основным списком реестра и нашим аудитом."
        };
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

    private static string VerdictTitle(
        ExternalUtilityVerdictLevel level,
        ExternalUtilityRow row,
        bool isOtherTraces,
        ExternalUtilityIdentifierInfo identifier)
    {
        var isUsbDeview = row.UtilityName.Contains("USBDeview", StringComparison.OrdinalIgnoreCase)
                          || row.SectionTitle.Contains("USBDeview", StringComparison.OrdinalIgnoreCase);

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
            return "VMware Workstation/Player — виртуальный USB (VID 0E0F, база USB ID: VMware, Inc.).";
        }

        if (identifier.VendorLookup.HasVendor && isOtherTraces)
        {
            return $"Косвенный след с кодом {identifier.Vid} ({identifier.VendorLookup.VendorName}) — USBDetector видит ключ Windows, полный аудит не подтверждает физическое USB.";
        }

        if (matches.Count > 0)
        {
            var utility = row.UtilityName.Contains("USBDeview", StringComparison.OrdinalIgnoreCase) ? "USBDeview" : "USBDetector";
            return $"Подтверждение в нашем аудите ({matches[0].SourceText}). {utility} и наш аудит ссылаются на одно и то же VID/PID.";
        }

        if (isOtherTraces)
        {
            var text = string.Join(' ', row.Values.Values).ToUpperInvariant();
            if (text.Contains("MOUNTED") || text.Contains("MOUNT"))
            {
                return "Вероятно MountedDevices / буква диска — след монтирования, не обязательно история флешки.";
            }

            if (text.Contains("MRU") || text.Contains("RECENT"))
            {
                return "Вероятно MRU/Recent пользователя — след обращения к пути, не факт подключения USB.";
            }

            return "Косвенный ключ Windows (MRU, MountedDevices, профиль, старый реестр) — источник видит только USBDetector.";
        }

        return "Запись реестра USB/USBSTOR или список USBDeview.";
    }

    private static string ResolveUsbDetectorNote(
        ExternalUtilityRow row,
        ExternalUtilityIdentifierInfo identifier,
        bool isOtherTraces,
        bool hasEpochDate,
        bool beforeOsInstall,
        int matchCount)
    {
        var isUsbDeview = row.UtilityName.Contains("USBDeview", StringComparison.OrdinalIgnoreCase);

        if (isUsbDeview && matchCount > 0)
        {
            return "USBDeview и наш аудит совпали по VID/PID — строка подтверждена.";
        }

        if (isUsbDeview && !identifier.HasVid)
        {
            return "Не найдены колонки Vendor ID / Product ID — проверьте, что считывание захватило все колонки USBDeview.";
        }

        if (isUsbDeview && identifier.HasVid && matchCount == 0)
        {
            return $"VID/PID {identifier.VidPidText} есть в USBDeview, но в полном аудите совпадений нет — возможно след удалён или устройство только в истории USBDeview.";
        }
        if (!string.IsNullOrWhiteSpace(identifier.ParseNote)
            && identifier.ParseMethod.Contains("Обрезан", StringComparison.OrdinalIgnoreCase))
        {
            return identifier.ParseNote + " База USB ID встроена в программу (формат usb.ids).";
        }

        if (hasEpochDate)
        {
            return "Колонка «Установка»/«Первое подключение» = 01.01.1970 из-за нулевого FILETIME. Это особенность USBDetector, не реальная дата.";
        }

        if (beforeOsInstall)
        {
            return "Дата раньше установки Windows — USBDetector мог взять косвенный источник. Не считать доказательством подключения до переустановки.";
        }

        if (isOtherTraces && matchCount == 0 && identifier.HasVid && !identifier.HasFullPair)
        {
            return "USBDetector передал неполный идентификатор (только VID). Это не «склеивание» префикса нашим приложением — так отображает утилита или обрезает колонку.";
        }

        if (isOtherTraces && matchCount == 0)
        {
            return "Строка только в «Других следах» и без совпадения в нашем аудите — типичный косвенный след, не обязательно ошибка USBDetector.";
        }

        if (isOtherTraces)
        {
            return "Раздел «Другие следы» намеренно широкий: USBDetector показывает всё подозрительное, часть строк — не про физическое USB.";
        }

        return "Основной список ближе к реальным записям реестра; всё равно сверяйте с нашим сканированием.";
    }

    private static string ResolveAuditMatchSummary(
        IReadOnlyList<UsbDeviceRecord> matches,
        AuditResult? audit,
        bool isOtherTraces)
    {
        if (audit is null)
        {
            return "Сканирование не выполнялось — сначала «Полное сканирование».";
        }

        if (matches.Count == 0)
        {
            return isOtherTraces
                ? "Совпадений нет — для «Других следов» это часто означает косвенную запись, а не пропущенную флешку."
                : "Совпадений нет — проверьте setupapi.dev.log и вкладку «Доказательства».";
        }

        return $"Найдено совпадений: {matches.Count} — устройство(а) есть в нашем аудите.";
    }

    private static IEnumerable<UsbDeviceRecord> FindMatchingDevices(
        ExternalUtilityRow row,
        AuditResult audit,
        ExternalUtilityIdentifierInfo identifier)
    {
        var vid = identifier.Vid;
        var pid = identifier.Pid;
        var serial = FindValue(row, "Serial", "Серийный номер", "UID");
        var name = FindValue(row, "Модель", "Model", "Производитель", "Manufacturer", "Носитель информации", "UID");

        return audit.Devices.Where(device =>
        {
            if (!string.IsNullOrWhiteSpace(vid)
                && !string.IsNullOrWhiteSpace(pid)
                && device.Vid.Equals(vid, StringComparison.OrdinalIgnoreCase)
                && device.Pid.Equals(pid, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!string.IsNullOrWhiteSpace(vid)
                && string.IsNullOrWhiteSpace(pid)
                && device.Vid.Equals(vid, StringComparison.OrdinalIgnoreCase))
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
