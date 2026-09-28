namespace UsbForensicAudit;

public static class UserDisplayText
{
    public const string NoDisconnectEvent = "Windows не зафиксировала отключение";
    public const string ConnectedNow = "Подключено сейчас";
    public const string NotConnectedUnknown = "Сейчас не подключено, время неизвестно";
    public const string NotApplicableDisconnect = "Не применимо";
    public const string NoFirstConnectEvent = "точное время неизвестно";
    public const string NoLastSeenEvent = "нет последних событий";
    public const string NoLocationData = "Windows не сохранила расположение порта";

    // Вычисляется и для старых сохранённых сессий: исходные доказательства
    // не требуется переписывать ради исправления подписи в таблице и отчёте.
    public static string DeviceCategory(UsbDeviceRecord device)
    {
        if (BluetoothEnumeratorId.IsPairedDeviceRecord(device.DeviceInstanceId))
        {
            return "Сопряжённое Bluetooth-устройство";
        }
        if (BluetoothEnumeratorId.IsServiceRecord(device.DeviceInstanceId))
        {
            return "Служба Bluetooth-устройства";
        }
        if (DeviceComposition.IsVolumeMetadata(device))
        {
            return device.DeviceType.Equals("VolumeLabel", StringComparison.OrdinalIgnoreCase)
                ? "Метка тома Windows"
                : "Сопоставление тома Windows";
        }
        if (device.DeviceType.Equals("DeviceInterface", StringComparison.OrdinalIgnoreCase))
        {
            return "След устройства (DeviceClasses)";
        }
        if (device.Transport is "Internal NVMe" or "Internal Disk")
        {
            return "Внутренний накопитель";
        }
        if (DeviceComposition.IsWpdUsbStorage(device))
        {
            return "USB-накопитель (запись WPD)";
        }
        return Category(device.VisualCategory);
    }

    public static string Category(string? value) => value switch
    {
        "RealUsb" => "Реальное USB-устройство",
        "BluetoothDevice" => "Сопряжённое Bluetooth-устройство",
        "RelatedStorage" => "Память или диск USB",
        "UsbFlagsTrace" => "Остаточный след USB (usbflags)",
        "SupportArtifact" => "Служебная запись Windows",
        "HistoricalResidual" => "След прошлого подключения",
        _ => "Не определено"
    };

    public static string Severity(string? value) => value?.ToUpperInvariant() switch
    {
        "HIGH" => "Высокий",
        "MEDIUM" => "Средний",
        "LOW" => "Низкий",
        "INFO" => "Информация",
        _ => value ?? ""
    };

    public static string Assessment(string? value) => value switch
    {
        "OsInstall" => "Контекст установки ОС",
        "Suspicious" => "Подозрительно",
        "Informational" => "Информационно",
        _ => value ?? "Подозрительно"
    };

    public static string InitiatorDisplay(string? kind, string? account)
    {
        var info = new InitiatorInfo(kind ?? "Unknown", account ?? "не определено", null);
        return info.DisplayText;
    }

    public static string Confidence(string? value) => value switch
    {
        "Normal" => "Контекст установки ОС",
        "Confirmed" => "Подтверждено",
        "Probable" => "Вероятно",
        "Indirect" => "Косвенный след",
        "ContextRequired" => "Требуется контекст",
        "Unknown" => "Не определено",
        _ => value ?? "Не определено"
    };

    public static string Area(string? value) => value switch
    {
        "SetupAPI" => "Журнал установки устройств",
        "Event Logs" => "Журналы Windows",
        "Cleaner Artifacts" => "Программы очистки следов",
        "USB Oblivion" => "USB Oblivion — удаление следов",
        "Correlation" => "Противоречия между источниками",
        _ => value ?? ""
    };

    public static string ActionKind(string? value) => value switch
    {
        "ToolLaunch" => "Запуск утилиты",
        "ToolPresence" => "След наличия утилиты",
        "ExecutionGap" => "Запуск без Prefetch",
        "ProbableCleanup" => "Вероятная очистка",
        "LogClearing" => "Очистка журналов",
        "RegistryArtifact" => "Изменение реестра/файлов",
        "Correlation" => "Противоречие источников",
        "ControlSetDifference" => "Различие ControlSet",
        "NormalMigrationContext" => "Штатная миграция/ротация Windows",
        "OsInstall" => "Контекст установки ОС",
        _ => "Не определено"
    };

    public static string Source(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        if (value.Equals("Registry: USB", StringComparison.OrdinalIgnoreCase))
        {
            return "Реестр Windows — USB-устройства";
        }

        if (value.Contains("usbflags", StringComparison.OrdinalIgnoreCase))
        {
            return "Реестр Windows — кэш USB-дескрипторов (usbflags)";
        }

        if (value.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))
        {
            return "Реестр Windows — USB-накопители";
        }

        if (value.Contains("SCSI", StringComparison.OrdinalIgnoreCase))
        {
            return "Реестр Windows — диски";
        }

        if (value.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase))
        {
            return "Реестр Windows — буквы дисков";
        }

        if (value.Contains("setupapi", StringComparison.OrdinalIgnoreCase))
        {
            return "Журнал установки Windows (setupapi.dev.log)";
        }

        if (value.StartsWith("EventLog:", StringComparison.OrdinalIgnoreCase))
        {
            return "Журнал Windows — " + value["EventLog:".Length..];
        }

        if (value.Contains("Prefetch", StringComparison.OrdinalIgnoreCase))
        {
            return "Prefetch — следы запуска программ";
        }

        if (value.Contains("Amcache", StringComparison.OrdinalIgnoreCase))
        {
            return "Amcache — следы установленных программ";
        }

        if (value.Contains("LNK", StringComparison.OrdinalIgnoreCase))
        {
            return "Ярлыки пользователя (.lnk)";
        }

        if (value.Contains("JumpList", StringComparison.OrdinalIgnoreCase))
        {
            return "Jump Lists — недавние файлы";
        }

        if (value.Contains("Hive", StringComparison.OrdinalIgnoreCase))
        {
            return "Профиль пользователя Windows";
        }

        if (value.Equals("Correlation", StringComparison.OrdinalIgnoreCase))
        {
            return "Автоматическая связь данных";
        }

        if (value.Contains("Журнал контроля USB", StringComparison.OrdinalIgnoreCase))
        {
            return "Журнал корпоративной защиты USB (DLP)";
        }

        return ReportText.ForDisplay(value, 220);
    }

    public static string DateConfidence(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        if (value.Contains("Служебный артефакт", StringComparison.OrdinalIgnoreCase))
        {
            return "Это не само устройство, а служебная запись Windows — даты здесь не показываются.";
        }

        if (value.Contains("Даты взяты из журнала Windows", StringComparison.OrdinalIgnoreCase))
        {
            return "Даты взяты из журналов Windows — это наиболее надёжные значения.";
        }

        if (value.Contains("оценено по последней активности", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Показана дата последней активности", StringComparison.OrdinalIgnoreCase))
        {
            return "Точное отключение не найдено. Показана дата последней активности — устройство сейчас не подключено.";
        }

        if (value.Contains("Сейчас не подключено", StringComparison.OrdinalIgnoreCase))
        {
            return "Устройство сейчас не подключено, но точное время отключения Windows не записала.";
        }

        if (value.Contains("Сейчас устройство снова подключено", StringComparison.OrdinalIgnoreCase))
        {
            return value;
        }

        if (value.Contains("события подключения не найдено", StringComparison.OrdinalIgnoreCase))
        {
            return "Устройство видно в системе, но точное время первого подключения не найдено.";
        }

        if (value.Contains("Есть запись в Registry", StringComparison.OrdinalIgnoreCase))
        {
            return "Windows помнит устройство, но когда его подключали или отключали — неизвестно.";
        }

        return value;
    }

    public static string VidPid(string vid, string pid) => VidPidCodes(vid, pid);

    public static string VidPidCodes(string vid, string pid)
    {
        if (string.IsNullOrWhiteSpace(vid) && string.IsNullOrWhiteSpace(pid))
        {
            return "не указаны";
        }

        if (string.IsNullOrWhiteSpace(vid))
        {
            return $"PID {pid}";
        }

        if (string.IsNullOrWhiteSpace(pid))
        {
            return $"VID {vid}";
        }

        return $"VID {vid} / PID {pid}";
    }

    /// <summary>
    /// Имя устройства для таблицы. Windows часто хранит имя ссылкой на строку в
    /// файле драйвера, поэтому каждое значение сначала разбирается: без этого во
    /// вкладке стояло «@usb.inf,%usb\composite.devicedesc%;USB Composite Device»
    /// вместо «USB Composite Device».
    /// </summary>
    public static string DeviceDisplayName(UsbDeviceRecord record)
    {
        var resolved = DeviceDisplayName(record.FriendlyName, record.Manufacturer, record.Product, record.DeviceInstanceId);
        var genericUsb = resolved.Equals("USB", StringComparison.OrdinalIgnoreCase)
            || resolved.Equals("USB Device", StringComparison.OrdinalIgnoreCase)
            || resolved.Equals("USB-устройство", StringComparison.OrdinalIgnoreCase);
        if (!genericUsb && !string.IsNullOrWhiteSpace(resolved) && !DeviceNameQuality.LooksLikeIdentifier(resolved))
        {
            return resolved;
        }

        if (record.DeviceType.Equals("USBFlags", StringComparison.OrdinalIgnoreCase)
            || record.Source.Contains("usbflags", StringComparison.OrdinalIgnoreCase))
        {
            return "Кэш USB-дескрипторов";
        }
        var pair = DeviceIdentifierMetadata.Pair(record.DeviceInstanceId);
        var isUsb = record.Transport.Contains("USB", StringComparison.OrdinalIgnoreCase)
            || record.Transport == "UASP/SCSI" || pair.HasValue
            || record.DeviceInstanceId.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
            || record.DeviceInstanceId.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase);
        if (!isUsb && !genericUsb)
        {
            return resolved;
        }

        var model = IndirectString.Resolve(record.Product);
        if (genericUsb && model.Length > 0 && !DeviceNameQuality.IsClassName(model))
        {
            return model;
        }

        var kind = record.DeviceKind == DeviceKindResolver.Storage || record.DeviceInstanceId.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
            ? "USB-накопитель" : record.DeviceKind == DeviceKindResolver.PortableDevice ? "Переносимое USB-устройство" : "USB-устройство";
        var vendor = UsbVendorDatabase.Lookup(record.Vid.Length > 0 ? record.Vid : pair?.Vid).VendorName;
        return $"{kind}{(string.IsNullOrWhiteSpace(vendor) ? "" : " · " + vendor)} (модель неизвестна)";
    }

    public static string DeviceInstanceSummary(UsbDeviceRecord record)
    {
        var address = BluetoothEnumeratorId.DeviceAddress(record.DeviceInstanceId);
        if (address.Length > 0)
        {
            return "Bluetooth · " + string.Join(":", Enumerable.Range(0, 6).Select(i => address.Substring(i * 2, 2)));
        }

        if (record.DeviceType.Equals("USBFlags", StringComparison.OrdinalIgnoreCase)
            || record.Source.Contains("usbflags", StringComparison.OrdinalIgnoreCase))
        {
            return "Общий кэш модели, без серийного номера";
        }

        var id = DevicePathNormalizer.NormalizeDeviceId(record.DeviceInstanceId, replaceHashes: true);
        var tail = id.Split('\\', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "";
        var bus = id.StartsWith("USB", StringComparison.OrdinalIgnoreCase) || id.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase) ? "USB" : record.Transport;
        return tail.Length > 0 ? $"{bus} · экземпляр {tail}" : "Идентификатор экземпляра не сохранён";
    }

    public static string DeviceDisplayName(string friendlyName, string manufacturer, string product, string deviceInstanceId)
    {
        var name = IndirectString.Resolve(friendlyName);
        var vendor = IndirectString.Resolve(manufacturer);
        var model = IndirectString.Resolve(product);

        if (!string.IsNullOrWhiteSpace(name)
            && !name.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
            && !name.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase))
        {
            return name;
        }

        if (!string.IsNullOrWhiteSpace(vendor) && !string.IsNullOrWhiteSpace(model))
        {
            // «Microsoft Microsoft Bluetooth A2dp Sink» — имя производителя уже
            // стоит в названии модели, и повторять его незачем.
            return model.StartsWith(vendor, StringComparison.OrdinalIgnoreCase)
                ? model
                : $"{vendor} {model}".Trim();
        }

        if (!string.IsNullOrWhiteSpace(model))
        {
            return model;
        }

        if (!string.IsNullOrWhiteSpace(vendor))
        {
            return vendor;
        }

        return deviceInstanceId;
    }

    public static string ManufacturerName(string manufacturer, string friendlyName, string vid)
    {
        var vendor = IndirectString.Resolve(manufacturer);
        if (!string.IsNullOrWhiteSpace(vendor))
        {
            return vendor;
        }

        var name = IndirectString.Resolve(friendlyName);
        if (!string.IsNullOrWhiteSpace(name))
        {
            var parts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > 1 && !name.Contains("USB Device", StringComparison.OrdinalIgnoreCase))
            {
                return parts[0];
            }
        }

        return string.IsNullOrWhiteSpace(vid) ? "не определён" : $"неизвестен (VID {vid})";
    }

    public static string ModelName(string product, string friendlyName, string revision, string pid)
    {
        var model = IndirectString.Resolve(product);
        if (!string.IsNullOrWhiteSpace(model))
        {
            return string.IsNullOrWhiteSpace(revision) ? model : $"{model} {revision}".Trim();
        }

        var name = IndirectString.Resolve(friendlyName);
        if (!string.IsNullOrWhiteSpace(name))
        {
            if (name.Contains("USB Device", StringComparison.OrdinalIgnoreCase))
            {
                return name.Replace(" USB Device", "", StringComparison.OrdinalIgnoreCase).Trim();
            }

            var parts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > 1)
            {
                return string.Join(' ', parts.Skip(1));
            }

            return name;
        }

        return string.IsNullOrWhiteSpace(pid) ? "не определена" : $"неизвестна (PID {pid})";
    }

    public static string ConnectionText(string displayKind, DateTimeOffset? connectedUtc)
    {
        return displayKind switch
        {
            "ExactEvent" when connectedUtc.HasValue =>
                DateDisplay.FormatMoscow(connectedUtc.Value),
            "RegistryActivity" when connectedUtc.HasValue =>
                $"{DateDisplay.FormatMoscow(connectedUtc.Value)} (ориентир — запись в реестре)",
            "LiveAtScan" when connectedUtc.HasValue =>
                $"{DateDisplay.FormatMoscow(connectedUtc.Value)} (обнаружено при сканировании)",
            _ => NoFirstConnectEvent
        };
    }

    public static string DeviceStatus(string? wmiStatus, string deviceId)
    {
        var status = (wmiStatus ?? "").Trim();
        if (status.Equals("OK", StringComparison.OrdinalIgnoreCase))
        {
            return "Работает";
        }

        if (status.Equals("Error", StringComparison.OrdinalIgnoreCase))
        {
            if (deviceId.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
                || deviceId.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
                || deviceId.StartsWith(@"REMOVABLE\", StringComparison.OrdinalIgnoreCase))
            {
                if (EndpointProtectionState.IsProtectionActive)
                {
                    return "Подключено через корпоративную защиту USB (WMI показывает Error — это нормально для фильтра дисков)";
                }

                return "Подключено (WMI: Error — часто при активной DLP-защите)";
            }

            return "Ошибка WMI";
        }

        if (status.Equals("Degraded", StringComparison.OrdinalIgnoreCase))
        {
            return "Ограничено";
        }

        if (status.Equals("Unknown", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(status))
        {
            return "Неизвестно";
        }

        return status;
    }

    public static string DisconnectText(string displayKind, DateTimeOffset? disconnectedUtc, bool isCurrentlyConnected)
    {
        return displayKind switch
        {
            "ExactEvent" when disconnectedUtc.HasValue && isCurrentlyConnected =>
                $"{DateDisplay.FormatMoscow(disconnectedUtc.Value)} (сейчас снова подключено)",
            "ExactEvent" when disconnectedUtc.HasValue =>
                DateDisplay.FormatMoscow(disconnectedUtc.Value),
            "LastActivityEstimate" when disconnectedUtc.HasValue =>
                $"{DateDisplay.FormatMoscow(disconnectedUtc.Value)} (ориентир — последняя активность)",
            "ConnectedNow" => ConnectedNow,
            "NotConnectedUnknown" => NotConnectedUnknown,
            "NotApplicable" => NotApplicableDisconnect,
            _ => NoDisconnectEvent
        };
    }

    public static string Location(string locationInformation, string locationPaths)
    {
        if (!string.IsNullOrWhiteSpace(locationInformation))
        {
            return locationInformation;
        }

        if (!string.IsNullOrWhiteSpace(locationPaths))
        {
            return locationPaths;
        }

        return NoLocationData;
    }

    public static string Serial(string? serial)
    {
        return string.IsNullOrWhiteSpace(serial) ? "не указан" : serial;
    }

    public static string DeviceType(string? value) => value switch
    {
        "USBSTOR" => "USB-накопитель",
        "USB" => "USB-устройство",
        "HID" => "Мышь, клавиатура и т.п.",
        "WPD" => "Телефон / камера (MTP)",
        "SCSI" => "Диск",
        "USBFlags" => "Остаточный след usbflags",
        "VolumeMapping" => "Буква диска",
        _ => string.IsNullOrWhiteSpace(value) ? "не определено" : value
    };
}
