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

    public static string Category(string? value) => value switch
    {
        "RealUsb" => "Реальное USB-устройство",
        "RelatedStorage" => "Память или диск USB",
        "UsbFlagsTrace" => "Остаточный след USB (usbflags)",
        "SupportArtifact" => "Служебная запись Windows",
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
        "OsInstall" => "Норма: ОС после установки",
        "Suspicious" => "Подозрительно",
        _ => value ?? "Подозрительно"
    };

    public static string InitiatorDisplay(string? kind, string? account)
    {
        var info = new InitiatorInfo(kind ?? "Unknown", account ?? "не определено", null);
        return info.DisplayText;
    }

    public static string Confidence(string? value) => value switch
    {
        "Normal" => "Норма (после установки)",
        "Confirmed" => "Подтверждено",
        "Probable" => "Вероятно",
        "Indirect" => "Косвенный след",
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
        "ProbableCleanup" => "Вероятная очистка",
        "LogClearing" => "Очистка журналов",
        "RegistryArtifact" => "Изменение реестра/файлов",
        "Correlation" => "Противоречие источников",
        "OsInstall" => "Норма после установки ОС",
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

    public static string DeviceDisplayName(string friendlyName, string manufacturer, string product, string deviceInstanceId)
    {
        if (!string.IsNullOrWhiteSpace(friendlyName)
            && !friendlyName.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
            && !friendlyName.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase))
        {
            return friendlyName;
        }

        if (!string.IsNullOrWhiteSpace(manufacturer) && !string.IsNullOrWhiteSpace(product))
        {
            return $"{manufacturer} {product}".Trim();
        }

        if (!string.IsNullOrWhiteSpace(product))
        {
            return product;
        }

        if (!string.IsNullOrWhiteSpace(manufacturer))
        {
            return manufacturer;
        }

        return deviceInstanceId;
    }

    public static string ManufacturerName(string manufacturer, string friendlyName, string vid)
    {
        if (!string.IsNullOrWhiteSpace(manufacturer))
        {
            return manufacturer;
        }

        if (!string.IsNullOrWhiteSpace(friendlyName))
        {
            var parts = friendlyName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > 1 && !friendlyName.Contains("USB Device", StringComparison.OrdinalIgnoreCase))
            {
                return parts[0];
            }
        }

        return string.IsNullOrWhiteSpace(vid) ? "не определён" : $"неизвестен (VID {vid})";
    }

    public static string ModelName(string product, string friendlyName, string revision, string pid)
    {
        if (!string.IsNullOrWhiteSpace(product))
        {
            return string.IsNullOrWhiteSpace(revision) ? product : $"{product} {revision}".Trim();
        }

        if (!string.IsNullOrWhiteSpace(friendlyName))
        {
            if (friendlyName.Contains("USB Device", StringComparison.OrdinalIgnoreCase))
            {
                return friendlyName.Replace(" USB Device", "", StringComparison.OrdinalIgnoreCase).Trim();
            }

            var parts = friendlyName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > 1)
            {
                return string.Join(' ', parts.Skip(1));
            }

            return friendlyName;
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
