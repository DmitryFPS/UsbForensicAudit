namespace UsbForensicAudit;

/// <summary>
/// Насколько можно верить идентификаторам устройства. Раньше серийный номер и
/// пара VID/PID принимались как факт, хотя устройство сообщает их само и ничем
/// не подтверждает: дешёвые накопители массово продаются с одинаковыми
/// серийными номерами, а прошивку контроллера меняют утилитой за минуту.
/// Вывод «подключали именно эту флешку» на таком основании держится плохо, и
/// об этом лучше сказать прямо в отчёте, чем умолчать.
/// </summary>
public static class DeviceIdentityTrust
{
    /// <summary>
    /// Пары, которые контроллеры отдают «из коробки», если производитель не
    /// прошил свои. Встречаются у множества не связанных между собой изделий.
    /// </summary>
    private static readonly HashSet<string> DefaultVidPid = new(StringComparer.OrdinalIgnoreCase)
    {
        "0000:0000", "FFFF:FFFF", "1234:5678", "ABCD:1234", "DEAD:BEEF",
        "058F:6387", "090C:1000", "1234:1234", "0011:7788", "1005:B113"
    };

    private static readonly HashSet<string> PlaceholderVendorNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "General", "USB", "Generic", "UNKNOWN", "Vendor", "Ven", "OEM", "China", "MassStorage"
    };

    public static IReadOnlyList<IdentityTrustFinding> Assess(UsbDeviceRecord device)
    {
        var findings = new List<IdentityTrustFinding>();
        var serial = ExtractSerial(device);

        if (IsWindowsGeneratedSerial(serial))
        {
            findings.Add(new IdentityTrustFinding(
                "Серийный номер придуман Windows",
                "Устройство не сообщило собственный серийный номер, и система выдала ему временный. "
                + "Такой номер принадлежит не устройству, а конкретному разъёму и установке Windows: "
                + "то же устройство в другом порту получит другой номер, а другое устройство в этом "
                + "порту может получить такой же. Отождествлять устройства по нему нельзя.",
                "High"));
        }
        else if (IsRepeatedCharacterSerial(serial))
        {
            findings.Add(new IdentityTrustFinding(
                "Серийный номер состоит из повторяющегося знака",
                $"Серийный номер «{serial}» не выглядит уникальным. Такие номера прошивают партиями, "
                + "и совпадение серийных номеров у двух устройств ничего не доказывает.",
                "Medium"));
        }
        else if (IsPlaceholderSerial(serial))
        {
            findings.Add(new IdentityTrustFinding(
                "Серийный номер выглядит как значение по умолчанию",
                $"Серийный номер «{serial}» — шаблонная последовательность, которую контроллеры "
                + "отдают, когда собственный номер в прошивку не записан. Такие номера встречаются "
                + "у множества не связанных между собой изделий, поэтому по нему нельзя ни опознать "
                + "устройство, ни утверждать, что два следа оставлены одним и тем же носителем.",
                "High"));
        }

        var vidPid = $"{device.Vid}:{device.Pid}";
        if (DefaultVidPid.Contains(vidPid))
        {
            findings.Add(new IdentityTrustFinding(
                "Заводские значения VID и PID",
                $"Пара {vidPid} — то, что контроллер отдаёт, если производитель не прошил свои значения. "
                + "Она встречается у множества не связанных между собой изделий, поэтому определить "
                + "по ней конкретную модель нельзя.",
                "Medium"));
        }

        if (!string.IsNullOrWhiteSpace(device.Vid) && !IsHex(device.Vid))
        {
            findings.Add(new IdentityTrustFinding(
                "VID не является шестнадцатеричным числом",
                $"Значение «{device.Vid}» не может быть настоящим идентификатором производителя: "
                + "по спецификации USB это четыре шестнадцатеричные цифры. Запись либо повреждена, "
                + "либо идентификаторы подменены.",
                "High"));
        }

        if (PlaceholderVendorNames.Contains(device.Manufacturer.Trim())
            || PlaceholderVendorNames.Contains(ExtractVendorFromInstanceId(device)))
        {
            findings.Add(new IdentityTrustFinding(
                "Имя производителя не указано",
                "В строке производителя стоит заглушка, а не название компании. Само по себе это "
                + "обычно для дешёвых накопителей, но опознать изделие по такой записи невозможно.",
                "Low"));
        }

        return findings;
    }

    /// <summary>
    /// Проверки, которые видны только на всём наборе: одинаковый серийный номер
    /// у разных моделей означает, что номер прошит партией и никого не
    /// идентифицирует.
    /// </summary>
    public static IReadOnlyList<(UsbDeviceRecord Device, IdentityTrustFinding Finding)> AssessAll(
        IEnumerable<UsbDeviceRecord> devices)
    {
        var records = devices as IReadOnlyList<UsbDeviceRecord> ?? devices.ToArray();
        var results = new List<(UsbDeviceRecord, IdentityTrustFinding)>();

        foreach (var device in records)
        {
            foreach (var finding in Assess(device))
            {
                results.Add((device, finding));
            }
        }

        var bySerial = records
            .Where(x => !string.IsNullOrWhiteSpace(ExtractSerial(x)) && !IsWindowsGeneratedSerial(ExtractSerial(x)))
            .GroupBy(ExtractSerial, StringComparer.OrdinalIgnoreCase);

        foreach (var group in bySerial)
        {
            var models = group
                .Select(x => $"{x.Vid}:{x.Pid}")
                .Where(x => x != ":")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (models.Length < 2)
            {
                continue;
            }

            foreach (var device in group)
            {
                results.Add((device, new IdentityTrustFinding(
                    "Один серийный номер у разных моделей",
                    $"Серийный номер «{group.Key}» встречается у устройств с разными VID/PID "
                    + $"({string.Join(", ", models)}). Значит, он прошит партией и конкретное "
                    + "устройство по нему не опознаётся.",
                    "High")));
            }
        }

        return results;
    }

    /// <summary>
    /// Windows подставляет собственный номер, когда устройство своего не сообщило.
    /// Признак задан спецификацией: второй знак идентификатора экземпляра — «и».
    /// </summary>
    public static bool IsWindowsGeneratedSerial(string? serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
        {
            return false;
        }

        var value = serial.Trim();
        return value.Length > 1 && value[1] == '&';
    }

    /// <summary>
    /// Известные шаблонные номера и монотонные последовательности вроде
    /// 0123456789ABCDEF или 12345678. Контроллер отдаёт их, когда собственный
    /// номер в прошивку не записан, — то есть номер принадлежит не изделию, а
    /// эталонной прошивке, и на нём нельзя строить вывод об одном и том же
    /// носителе.
    /// </summary>
    public static bool IsPlaceholderSerial(string? serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
        {
            return false;
        }

        var value = serial.Trim().Split('&')[0];
        if (value.Length < 6)
        {
            return false;
        }

        if (KnownPlaceholderSerials.Contains(value))
        {
            return true;
        }

        return IsMonotonicSequence(value);
    }

    private static readonly HashSet<string> KnownPlaceholderSerials = new(StringComparer.OrdinalIgnoreCase)
    {
        "0123456789ABCDEF", "0123456789", "123456789", "12345678", "1234567890",
        "000000000000", "111111111111", "0123456789AB", "DEADBEEF", "ABCDEF",
        "SERIALNUMBER", "0000000000000000", "NONE", "DEFAULT", "0123456789ABCDE"
    };

    /// <summary>
    /// Номер, знаки которого идут строго подряд по коду в одну сторону: 12345678,
    /// ABCDEFGH, 98765432. Настоящий серийный номер так не выглядит.
    /// </summary>
    private static bool IsMonotonicSequence(string value)
    {
        if (!value.All(char.IsAsciiLetterOrDigit))
        {
            return false;
        }

        var step = value[1] - value[0];
        if (step is not (1 or -1))
        {
            return false;
        }

        for (var index = 2; index < value.Length; index++)
        {
            if (value[index] - value[index - 1] != step)
            {
                return false;
            }
        }

        return true;
    }

    public static bool IsRepeatedCharacterSerial(string? serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
        {
            return false;
        }

        // Windows дописывает к серийному номеру номер экземпляра через «и»,
        // и его нужно отбросить, иначе номер из одних нулей выглядит разнородным.
        var value = serial.Trim().Split('&')[0];
        return value.Length >= 4 && value.Distinct().Count() == 1;
    }

    private static string ExtractSerial(UsbDeviceRecord device)
    {
        if (!string.IsNullOrWhiteSpace(device.Serial))
        {
            return device.Serial.Trim();
        }

        var parts = device.DeviceInstanceId.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 3 ? parts[^1].Trim() : "";
    }

    private static string ExtractVendorFromInstanceId(UsbDeviceRecord device)
    {
        const string marker = "Ven_";
        var index = device.DeviceInstanceId.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return "";
        }

        var tail = device.DeviceInstanceId[(index + marker.Length)..];
        var end = tail.IndexOfAny(['&', '\\']);
        return (end < 0 ? tail : tail[..end]).Trim();
    }

    private static bool IsHex(string value) =>
        value.All(ch => char.IsAsciiHexDigit(ch));
}

public sealed record IdentityTrustFinding(string Title, string Explanation, string Severity)
{
    public string SeverityText => Severity switch
    {
        "High" => "идентификатору верить нельзя",
        "Medium" => "идентификатор ненадёжен",
        _ => "замечание"
    };
}
