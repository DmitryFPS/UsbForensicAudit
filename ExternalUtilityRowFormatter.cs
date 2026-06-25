using System.Text;

namespace UsbForensicAudit;

public static class ExternalUtilityRowFormatter
{
    private static readonly string[] SummaryKeys =
    [
        "VID", "Vendor ID", "PID", "Product ID",
        "Производитель", "Manufacturer",
        "Модель", "Model",
        "Первое подключение", "First connection",
        "Установка", "Installation"
    ];

    private static readonly string[] DetailOrder =
    [
        "UID", "VID", "Vendor ID", "Производитель", "Manufacturer",
        "PID", "Product ID", "Модель", "Model", "Device Name", "Description", "Имя устройства",
        "Предназначение", "Носитель информации",
        "Первое подключение", "First connection", "Установка", "Installation", "Модификация",
        "Serial Number", "Instance ID", "Подключение", "Дата"
    ];

    public static string KeyFieldsText(ExternalUtilityRow row)
    {
        var parts = new List<string>();

        var vid = FindValue(row, "VID", "Vendor ID");
        var pid = FindValue(row, "PID", "Product ID");
        if (!string.IsNullOrWhiteSpace(vid) || !string.IsNullOrWhiteSpace(pid))
        {
            parts.Add($"VID/PID: {FormatVidPid(vid, pid)}");
        }

        var manufacturer = FindValue(row, "Производитель", "Manufacturer");
        if (!string.IsNullOrWhiteSpace(manufacturer))
        {
            parts.Add($"Произв.: {manufacturer}");
        }

        var model = FindValue(row, "Модель", "Model");
        if (!string.IsNullOrWhiteSpace(model))
        {
            parts.Add($"Модель: {model}");
        }

        var date = ExternalUtilityColumnNormalizer.FindConnectionDate(row.Values);
        if (!string.IsNullOrWhiteSpace(date))
        {
            parts.Add($"Дата: {date}");
        }

        if (parts.Count == 0)
        {
            return row.PrimaryText;
        }

        return string.Join(" · ", parts);
    }

    public static string FormattedDetailsText(ExternalUtilityRow row)
    {
        var builder = new StringBuilder();
        var usedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var key in DetailOrder)
        {
            if (!row.Values.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (!usedKeys.Add(key))
            {
                continue;
            }

            builder.AppendLine($"{ReadableLabel(key)}: {value}");
        }

        foreach (var pair in row.Values.OrderBy(x => FieldOrder(x.Key)))
        {
            if (string.IsNullOrWhiteSpace(pair.Value) || usedKeys.Contains(pair.Key))
            {
                continue;
            }

            builder.AppendLine($"{ReadableLabel(pair.Key)}: {pair.Value}");
        }

        return builder.ToString().TrimEnd();
    }

    public static string CopyText(ExternalUtilityRow row)
    {
        var ordered = row.Values
            .Where(x => !string.IsNullOrWhiteSpace(x.Value))
            .OrderBy(x => FieldOrder(x.Key))
            .ToArray();

        if (ordered.Length == 0)
        {
            return row.PrimaryText;
        }

        return string.Join('\t', ordered.Select(x => x.Value));
    }

    public static string CopyTextWithHeaders(ExternalUtilityRow row)
    {
        var ordered = row.Values
            .Where(x => !string.IsNullOrWhiteSpace(x.Value))
            .OrderBy(x => FieldOrder(x.Key))
            .ToArray();

        if (ordered.Length == 0)
        {
            return row.PrimaryText;
        }

        return string.Join('\t', ordered.Select(x => x.Value));
    }

    private static string FormatVidPid(string vid, string pid)
    {
        if (!string.IsNullOrWhiteSpace(vid) && !string.IsNullOrWhiteSpace(pid))
        {
            return $"{vid}/{pid}";
        }

        return !string.IsNullOrWhiteSpace(vid) ? vid : pid;
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

    private static string ReadableLabel(string key) => key switch
    {
        "UID" => "UID",
        "VID" or "Vendor ID" => "VID",
        "PID" or "Product ID" => "PID",
        "Device Name" or "Имя устройства" => "Имя",
        "Manufacturer" or "Производитель" => "Производитель",
        "Model" or "Модель" => "Модель",
        "First connection" or "Первое подключение" => "Первое подключение",
        "Installation" or "Установка" => "Установка",
        "Модификация" => "Модификация",
        _ => key.StartsWith("Поле ", StringComparison.Ordinal) || key.StartsWith("Колонка ", StringComparison.OrdinalIgnoreCase)
            ? key
            : key
    };

    private static int FieldOrder(string key)
    {
        for (var index = 0; index < DetailOrder.Length; index++)
        {
            if (key.Equals(DetailOrder[index], StringComparison.OrdinalIgnoreCase))
            {
                return index;
            }
        }

        if (key.StartsWith("Поле ", StringComparison.Ordinal))
        {
            return 100 + (int.TryParse(key["Поле ".Length..], out var n) ? n : 0);
        }

        if (key.StartsWith("Колонка ", StringComparison.OrdinalIgnoreCase))
        {
            return 200 + (int.TryParse(key["Колонка ".Length..], out var n) ? n : 0);
        }

        return 150;
    }
}
