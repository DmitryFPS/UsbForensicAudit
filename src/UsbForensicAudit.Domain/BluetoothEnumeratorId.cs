using System.Text.RegularExpressions;

namespace UsbForensicAudit;

/// <summary>
/// Записи шины Bluetooth бывают двух видов, и путать их нельзя.
///
/// «BTHENUM\Dev_887598C2F5F2\...» — само сопряжённое устройство: телефон,
/// гарнитура, часы. Его кто-то принёс с собой.
///
/// «BTHENUM\{0000111f-0000-1000-8000-00805f9b34fb}_VID&amp;...\...» — одна из
/// услуг того же устройства: громкая связь, передача файлов, выход в сеть.
/// Windows заводит такую запись на каждый профиль, и у одного телефона их
/// полтора десятка. Показывать каждую как отдельное принесённое устройство
/// значит завысить число устройств во вкладке в пятнадцать раз.
/// </summary>
public static class BluetoothEnumeratorId
{
    private static readonly string[] Buses = [@"BTHENUM\", @"BTHLEDEVICE\", @"BTHLE\"];

    /// <summary>Запись описывает услугу сопряжённого устройства, а не его само.</summary>
    public static bool IsServiceRecord(string? deviceInstanceId) =>
        TryReadServiceUuid(deviceInstanceId, out _);

    /// <summary>Адрес удалённого устройства, а не общий префикс Bluetooth-адаптера.</summary>
    public static string DeviceAddress(string deviceInstanceId)
    {
        var parts = DevicePathNormalizer.CanonicalDeviceId(deviceInstanceId, replaceHashes: true).Split('\\');
        if (parts.Length != 3 || parts[0] is not ("BTHENUM" or "BTHLEDEVICE" or "BTHLE"))
        {
            return "";
        }

        var match = Regex.Match(parts[1], @"^(?:DEV_|\{[0-9A-F-]{36}\}_)([0-9A-F]{12})$", RegexOptions.CultureInvariant);
        if (!match.Success && parts[0] == "BTHENUM")
        {
            match = Regex.Match(parts[2], @"(?:^|&)(?:BLUETOOTHDEVICE_)?([0-9A-F]{12})(?:_C[0-9A-F]{8})?$", RegexOptions.CultureInvariant);
        }

        var address = match.Success ? match.Groups[1].Value : "";
        return address is "000000000000" or "FFFFFFFFFFFF" ? "" : address;
    }

    /// <summary>Запись описывает само сопряжённое устройство.</summary>
    public static bool IsPairedDeviceRecord(string? deviceInstanceId)
    {
        var rest = AfterBus(deviceInstanceId);
        return rest.StartsWith("Dev_", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Опознаватель услуги из идентификатора записи. По нему услугу можно
    /// назвать словами и объяснить, что через это соединение было можно.
    /// </summary>
    public static bool TryReadServiceUuid(string? deviceInstanceId, out string uuid)
    {
        uuid = "";
        var rest = AfterBus(deviceInstanceId);
        if (!rest.StartsWith('{'))
        {
            return false;
        }

        var end = rest.IndexOf('}');
        if (end < 0)
        {
            return false;
        }

        uuid = rest[..(end + 1)];
        return true;
    }

    private static string AfterBus(string? deviceInstanceId)
    {
        var text = (deviceInstanceId ?? "").TrimStart();
        foreach (var bus in Buses)
        {
            if (text.StartsWith(bus, StringComparison.OrdinalIgnoreCase))
            {
                return text[bus.Length..];
            }
        }

        return "";
    }
}
