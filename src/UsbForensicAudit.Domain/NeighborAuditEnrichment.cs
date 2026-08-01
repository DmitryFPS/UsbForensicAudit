namespace UsbForensicAudit;

/// <summary>
/// Даёт соседям по сети имена из результатов полного аудита машины.
///
/// Телефон, который молчит на все сетевые вопросы, машина может знать по
/// другой линии: он сопрягался по Bluetooth или подключался проводом, и его
/// имя лежит в реестре. Совпадение ищется по аппаратному адресу — двенадцати
/// шестнадцатеричным знакам, зашитым в серийный номер или путь устройства.
/// </summary>
public static class NeighborAuditEnrichment
{
    /// <summary>Источник имени в колонке «Откуда имя».</summary>
    public const string SourceName = "аудит машины";

    public static void Enrich(
        IEnumerable<NetworkNeighborRecord> neighbors,
        IReadOnlyCollection<UsbDeviceRecord> devices)
    {
        var byMac = BuildMacIndex(devices);
        if (byMac.Count == 0)
        {
            return;
        }

        foreach (var neighbor in neighbors)
        {
            if (neighbor.HostName.Length > 0 || neighbor.NetbiosName.Length > 0)
            {
                continue;
            }

            var digits = HexDigits(neighbor.MacAddress);
            if (digits.Length != 12 || !byMac.TryGetValue(digits, out var name))
            {
                continue;
            }

            neighbor.EnrichedName = name;
            neighbor.NameSource = SourceName;
        }
    }

    private static Dictionary<string, string> BuildMacIndex(IReadOnlyCollection<UsbDeviceRecord> devices)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var device in devices)
        {
            var name = device.FriendlyName.Trim();
            if (name.Length == 0)
            {
                continue;
            }

            foreach (var candidate in ExtractMacCandidates(device))
            {
                result.TryAdd(candidate, name);
            }
        }

        return result;
    }

    private static IEnumerable<string> ExtractMacCandidates(UsbDeviceRecord device)
    {
        var serial = HexDigits(device.Serial);
        if (serial.Length == 12)
        {
            yield return serial;
        }

        // BTHENUM-пути хранят адрес устройства последними 12 знаками.
        var instance = HexDigits(TailSegment(device.DeviceInstanceId));
        if (instance.Length >= 12)
        {
            yield return instance[^12..];
        }
    }

    private static string TailSegment(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "";
        }

        var index = value.LastIndexOf('\\');
        return index >= 0 ? value[(index + 1)..] : value;
    }

    private static string HexDigits(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "";
        }

        Span<char> buffer = stackalloc char[value.Length];
        var length = 0;
        foreach (var symbol in value)
        {
            if (char.IsAsciiHexDigit(symbol))
            {
                buffer[length++] = char.ToUpperInvariant(symbol);
            }
            else if (symbol is not (':' or '-' or ' ' or '&' or '_'))
            {
                return "";
            }
        }

        return new string(buffer[..length]);
    }
}
