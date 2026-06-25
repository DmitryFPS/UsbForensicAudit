using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public sealed class ExternalUtilityIdentifierInfo
{
    public string? Vid { get; init; }
    public string? Pid { get; init; }
    public required string ParseMethod { get; init; }
    public string? ParseNote { get; init; }
    public UsbVendorLookup VendorLookup { get; init; } = new();

    public bool HasVid => !string.IsNullOrWhiteSpace(Vid);
    public bool HasFullPair => HasVid && !string.IsNullOrWhiteSpace(Pid);

    public string VidPidText => HasFullPair
        ? $"{Vid}/{Pid}"
        : HasVid
            ? Vid!
            : "—";

    public string VendorProductText =>
        string.IsNullOrWhiteSpace(VendorLookup.DeviceDescription) ? "—" : VendorLookup.DeviceDescription;
}

public static class ExternalUtilityIdentifierParser
{
    private static readonly Regex StandardVidPidRegex = new(
        @"VID[_&](?<vid>[0-9A-F]{4}).*?PID[_&](?<pid>[0-9A-F]{4})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex StandaloneVidRegex = new(
        @"\bVID[:\s_&]*(?<vid>[0-9A-F]{4})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex StandalonePidRegex = new(
        @"\bPID[:\s_&]*(?<pid>[0-9A-F]{4})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex BareHexTokenRegex = new(
        @"\b(?<hex>[0-9A-F]{4})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PlainHexRegex = new(
        @"^(?:0x)?(?<hex>[0-9A-F]{4})$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] VidColumnKeys =
    [
        "VID", "Vendor ID", "VendorID", "Vendor Id", "VendorId", "ID Vendor", "Код VID"
    ];

    private static readonly string[] PidColumnKeys =
    [
        "PID", "Product ID", "ProductID", "Product Id", "ProductId", "ID Product", "Код PID"
    ];

    private static readonly string[] InstanceColumnKeys =
    [
        "Instance ID", "InstanceID", "Device ID", "DeviceID", "Instance Id", "Device Instance Id"
    ];

    public static ExternalUtilityIdentifierInfo Parse(ExternalUtilityRow row)
    {
        var combined = BuildCombinedText(row);
        var primary = row.PrimaryText?.Trim() ?? "";

        if (TryParseFromDedicatedColumns(row, out var columnVid, out var columnPid))
        {
            return Build(
                columnVid,
                columnPid,
                columnPid is not null ? "Колонки VID/PID (USBDeview и аналоги)" : "Колонка VID (USBDeview и аналоги)",
                columnPid is null ? "PID в строке не указан — сопоставление только по VID." : null);
        }

        foreach (var instanceText in FindColumnValues(row, InstanceColumnKeys))
        {
            var instanceMatch = StandardVidPidRegex.Match(instanceText);
            if (instanceMatch.Success)
            {
                return Build(
                    instanceMatch.Groups["vid"].Value,
                    instanceMatch.Groups["pid"].Value,
                    "Instance ID / Device ID",
                    null);
            }
        }

        var standard = StandardVidPidRegex.Match(combined);
        if (standard.Success)
        {
            return Build(
                standard.Groups["vid"].Value,
                standard.Groups["pid"].Value,
                "Полный UID (VID_xxxx&PID_yyyy)",
                null);
        }

        var vidMatch = StandaloneVidRegex.Match(combined);
        var pidMatch = StandalonePidRegex.Match(combined);
        if (vidMatch.Success)
        {
            var note = pidMatch.Success
                ? null
                : "Передан только VID без PID — устройство определяется неполно.";
            return Build(
                vidMatch.Groups["vid"].Value,
                pidMatch.Success ? pidMatch.Groups["pid"].Value : null,
                pidMatch.Success ? "Отдельные поля VID и PID" : "Только VID в данных строки",
                note);
        }

        if (LooksLikeBareVid(primary))
        {
            return Build(
                primary,
                null,
                "Обрезанный код в первой колонке",
                "Показаны только 4 символа (скорее VID), без префикса VID_ и без PID.");
        }

        foreach (var value in row.Values.Values.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            var trimmed = value.Trim();
            if (!LooksLikeBareVid(trimmed))
            {
                continue;
            }

            if (UsbVendorDatabase.IsKnownVendor(trimmed))
            {
                return Build(
                    trimmed,
                    null,
                    "Короткий hex-код в ячейке таблицы",
                    $"Значение «{trimmed}» совпало с известным VID в базе USB ID.");
            }
        }

        var bareTokens = BareHexTokenRegex.Matches(combined)
            .Select(x => x.Groups["hex"].Value.ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (bareTokens.Length == 1 && UsbVendorDatabase.IsKnownVendor(bareTokens[0]))
        {
            return Build(
                bareTokens[0],
                null,
                "Единственный hex-код в строке",
                $"Код «{bareTokens[0]}» распознан как VID по базе USB ID.");
        }

        return new ExternalUtilityIdentifierInfo
        {
            ParseMethod = "VID/PID не распознан",
            ParseNote = string.IsNullOrWhiteSpace(combined)
                ? "В строке нет текста для разбора идентификатора."
                : "Не удалось выделить VID/PID — проверьте, что считаны колонки Vendor ID и Product ID."
        };
    }

    public static string BuildCombinedText(ExternalUtilityRow row)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(row.PrimaryText))
        {
            parts.Add(row.PrimaryText.Trim());
        }

        parts.AddRange(row.Values.Values.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()));
        return string.Join(' ', parts);
    }

    private static bool TryParseFromDedicatedColumns(ExternalUtilityRow row, out string? vid, out string? pid)
    {
        vid = null;
        pid = null;

        foreach (var value in FindColumnValues(row, VidColumnKeys))
        {
            if (TryParseHexId(value, out var parsedVid))
            {
                vid = parsedVid;
                break;
            }
        }

        foreach (var value in FindColumnValues(row, PidColumnKeys))
        {
            if (TryParseHexId(value, out var parsedPid))
            {
                pid = parsedPid;
                break;
            }
        }

        if (vid is null)
        {
            foreach (var pair in row.Values)
            {
                if (!ColumnNameLooksLikeVid(pair.Key) || !TryParseHexId(pair.Value, out var parsedVid))
                {
                    continue;
                }

                vid = parsedVid;
                break;
            }
        }

        if (pid is null)
        {
            foreach (var pair in row.Values)
            {
                if (!ColumnNameLooksLikePid(pair.Key) || !TryParseHexId(pair.Value, out var parsedPid))
                {
                    continue;
                }

                pid = parsedPid;
                break;
            }
        }

        return vid is not null || pid is not null;
    }

    private static IEnumerable<string> FindColumnValues(ExternalUtilityRow row, IEnumerable<string> keys)
    {
        foreach (var key in keys)
        {
            if (row.Values.TryGetValue(key, out var exact) && !string.IsNullOrWhiteSpace(exact))
            {
                yield return exact;
            }
        }

        foreach (var pair in row.Values)
        {
            if (keys.Any(key => pair.Key.Equals(key, StringComparison.OrdinalIgnoreCase))
                && !string.IsNullOrWhiteSpace(pair.Value))
            {
                yield return pair.Value;
            }
        }
    }

    private static bool ColumnNameLooksLikeVid(string columnName) =>
        columnName.Contains("Vendor", StringComparison.OrdinalIgnoreCase)
        && columnName.Contains("ID", StringComparison.OrdinalIgnoreCase);

    private static bool ColumnNameLooksLikePid(string columnName) =>
        columnName.Contains("Product", StringComparison.OrdinalIgnoreCase)
        && columnName.Contains("ID", StringComparison.OrdinalIgnoreCase);

    internal static bool TryParseHexId(string? text, out string hex)
    {
        hex = "";
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var trimmed = text.Trim();
        var match = PlainHexRegex.Match(trimmed);
        if (!match.Success)
        {
            return false;
        }

        hex = match.Groups["hex"].Value.ToUpperInvariant();
        return true;
    }

    private static ExternalUtilityIdentifierInfo Build(string? vid, string? pid, string method, string? note)
    {
        vid = string.IsNullOrWhiteSpace(vid) ? null : vid.ToUpperInvariant();
        pid = string.IsNullOrWhiteSpace(pid) ? null : pid.ToUpperInvariant();
        return new ExternalUtilityIdentifierInfo
        {
            Vid = vid,
            Pid = pid,
            ParseMethod = method,
            ParseNote = note,
            VendorLookup = UsbVendorDatabase.Lookup(vid, pid)
        };
    }

    private static bool LooksLikeBareVid(string text) =>
        TryParseHexId(text, out var hex) && UsbVendorDatabase.IsKnownVendor(hex);
}
