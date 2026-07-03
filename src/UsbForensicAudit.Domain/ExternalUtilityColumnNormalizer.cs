using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public static class ExternalUtilityColumnNormalizer
{
    private static readonly Regex DateLikeRegex = new(
        @"\d{1,2}\.\d{1,2}\.\d{2,4}(\s+\d{1,2}:\d{2})?",
        RegexOptions.Compiled);

    public static IReadOnlyList<string> NormalizeHeaders(IReadOnlyList<string> headers)
    {
        return headers.Select(NormalizeHeaderName).ToArray();
    }

    public static string NormalizeHeaderName(string header)
    {
        var text = header.Trim();
        if (string.IsNullOrWhiteSpace(text))
        {
            return header;
        }

        if (text.Equals("UID", StringComparison.OrdinalIgnoreCase))
        {
            return "UID";
        }

        if (text.Equals("VID", StringComparison.OrdinalIgnoreCase))
        {
            return "VID";
        }

        if (text.Equals("PID", StringComparison.OrdinalIgnoreCase))
        {
            return "PID";
        }

        if (text.StartsWith("Производ", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("Manufact", StringComparison.OrdinalIgnoreCase))
        {
            return "Производитель";
        }

        if (text.StartsWith("Модел", StringComparison.OrdinalIgnoreCase)
            || text.Equals("Model", StringComparison.OrdinalIgnoreCase))
        {
            return "Модель";
        }

        if (text.StartsWith("Первое подключ", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("First connection", StringComparison.OrdinalIgnoreCase))
        {
            return "Первое подключение";
        }

        if (text.StartsWith("Установ", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("Install", StringComparison.OrdinalIgnoreCase)
            || text.Equals("Created Date", StringComparison.OrdinalIgnoreCase))
        {
            return "Установка";
        }

        if (text.StartsWith("Модифик", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("Modified", StringComparison.OrdinalIgnoreCase)
            || text.Equals("Last Plug/Unplug Date", StringComparison.OrdinalIgnoreCase))
        {
            return "Модификация";
        }

        if (text.StartsWith("Vendor ID", StringComparison.OrdinalIgnoreCase))
        {
            return "Vendor ID";
        }

        if (text.StartsWith("Product ID", StringComparison.OrdinalIgnoreCase))
        {
            return "Product ID";
        }

        if (text.StartsWith("Device Name", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("Имя устрой", StringComparison.OrdinalIgnoreCase))
        {
            return "Device Name";
        }

        if (text.StartsWith("Serial", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("Серийн", StringComparison.OrdinalIgnoreCase))
        {
            return "Serial Number";
        }

        return text;
    }

    public static Dictionary<string, string> MapRowValues(
        IReadOnlyList<string> headers,
        IReadOnlyList<string> cells)
    {
        var raw = MapRawRowValues(headers, cells);
        return RemapMisalignedUsbDetectorRow(raw);
    }

    public static Dictionary<string, string> MapRawRowValues(
        IReadOnlyList<string> headers,
        IReadOnlyList<string> cells)
    {
        var normalizedHeaders = NormalizeHeaders(headers);
        var paddedCells = PadCells(cells, normalizedHeaders.Count);
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (var index = 0; index < normalizedHeaders.Count; index++)
        {
            AssignValue(values, normalizedHeaders[index], paddedCells[index]);
        }

        for (var index = normalizedHeaders.Count; index < paddedCells.Length; index++)
        {
            AssignValue(values, $"Колонка {index + 1}", paddedCells[index]);
        }

        return values;
    }

    public static bool LooksMisaligned(IReadOnlyDictionary<string, string> values)
    {
        if (values.TryGetValue("Производитель", out var manufacturer)
            && ExternalUtilityIdentifierParser.TryParseHexId(manufacturer, out _))
        {
            return true;
        }

        if (values.TryGetValue("Модель", out var model)
            && ExternalUtilityIdentifierParser.TryParseHexId(model, out _)
            && !values.Values.Any(LooksLikeDate))
        {
            return true;
        }

        foreach (var dateKey in new[] { "Установка", "Первое подключение", "Модификация", "Installation", "First connection" })
        {
            if (values.TryGetValue(dateKey, out var candidate)
                && ExternalUtilityIdentifierParser.TryParseHexId(candidate, out _))
            {
                return true;
            }
        }

        return false;
    }

    public static string? FindConnectionDate(IReadOnlyDictionary<string, string> values)
    {
        foreach (var key in new[]
                 {
                     "Первое подключение", "First connection", "Last Plug/Unplug Date",
                     "Created Date", "Установка", "Installation", "Модификация", "Modified"
                 })
        {
            if (values.TryGetValue(key, out var text) && LooksLikeDate(text))
            {
                return text;
            }
        }

        return values.Values.FirstOrDefault(LooksLikeDate);
    }

    private static Dictionary<string, string> RemapMisalignedUsbDetectorRow(Dictionary<string, string> values)
    {
        if (!LooksMisaligned(values))
        {
            return values;
        }

        var ordered = values
            .OrderBy(x => FieldIndex(x.Key))
            .Select(x => x.Value)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToArray();

        if (ordered.Length < 3)
        {
            return values;
        }

        var remapped = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var index = 0;

        if (index < ordered.Length && ExternalUtilityIdentifierParser.TryParseHexId(ordered[index], out var vid))
        {
            remapped["VID"] = vid;
            index++;
        }

        if (index < ordered.Length
            && !ExternalUtilityIdentifierParser.TryParseHexId(ordered[index], out _)
            && !LooksLikeDate(ordered[index]))
        {
            remapped["Производитель"] = ordered[index];
            index++;
        }

        if (index < ordered.Length && ExternalUtilityIdentifierParser.TryParseHexId(ordered[index], out var pid))
        {
            remapped["PID"] = pid;
            index++;
        }

        if (index < ordered.Length
            && !ExternalUtilityIdentifierParser.TryParseHexId(ordered[index], out _)
            && !LooksLikeDate(ordered[index]))
        {
            remapped["Модель"] = ordered[index];
            index++;
        }

        for (; index < ordered.Length; index++)
        {
            if (LooksLikeDate(ordered[index]))
            {
                AssignValue(remapped, "Первое подключение", ordered[index]);
                break;
            }
        }

        foreach (var pair in values)
        {
            if (remapped.ContainsKey(pair.Key) || string.IsNullOrWhiteSpace(pair.Value))
            {
                continue;
            }

            if (LooksLikeDate(pair.Value))
            {
                AssignValue(remapped, "Первое подключение", pair.Value);
            }
        }

        return remapped.Count >= 3 ? remapped : values;
    }

    private static void AssignValue(IDictionary<string, string> values, string key, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        values[key] = value;
    }

    private static string[] PadCells(IReadOnlyList<string> cells, int headerCount)
    {
        if (headerCount <= 0)
        {
            return cells.ToArray();
        }

        var padded = new string[Math.Max(headerCount, cells.Count)];
        for (var index = 0; index < padded.Length; index++)
        {
            padded[index] = index < cells.Count ? cells[index] : "";
        }

        return padded;
    }

    private static bool LooksLikeDate(string? text) =>
        !string.IsNullOrWhiteSpace(text) && DateLikeRegex.IsMatch(text.Trim());

    private static int FieldIndex(string key)
    {
        if (key.StartsWith("Колонка ", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(key["Колонка ".Length..], out var columnNumber))
        {
            return 100 + columnNumber;
        }

        if (key.StartsWith("Поле ", StringComparison.Ordinal)
            && int.TryParse(key["Поле ".Length..], out var fieldNumber))
        {
            return 100 + fieldNumber;
        }

        return NormalizeHeaderName(key) switch
        {
            "UID" => 0,
            "VID" or "Vendor ID" => 1,
            "Производитель" => 2,
            "PID" or "Product ID" => 3,
            "Модель" => 4,
            "Установка" => 8,
            "Модификация" => 9,
            "Первое подключение" => 10,
            _ => 50
        };
    }
}
