using System.Globalization;
using System.IO;
using System.Text;

namespace UsbForensicAudit;

/// <summary>
/// Один раздел из экспортированного файла реестра.
/// </summary>
public sealed class RegExportKey
{
    public string Path { get; init; } = "";
    public Dictionary<string, object?> Values { get; } = new(StringComparer.OrdinalIgnoreCase);

    public string GetString(string name) =>
        Values.TryGetValue(name, out var value) ? value switch
        {
            string text => text,
            string[] items => string.Join("; ", items),
            _ => ""
        } : "";

    public byte[]? GetBinary(string name) =>
        Values.TryGetValue(name, out var value) ? value as byte[] : null;
}

/// <summary>
/// Разбор файлов, полученных командой reg export. Это единственный формат, в
/// котором обычно приносят реестр с чужой машины: снять кусты целиком удаётся
/// не всегда, а экспорт делается без специальных прав.
/// </summary>
public static class RegExportParser
{
    public static IReadOnlyList<RegExportKey> ParseFile(string path) =>
        Parse(ReadAllText(path));

    /// <summary>
    /// Regedit сохраняет экспорт в UTF-16 с меткой порядка байтов, а старый
    /// формат REGEDIT4 — в однобайтовой кодировке. Определяем по метке.
    /// </summary>
    public static string ReadAllText(string path)
    {
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        }

        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
        }

        TextSanitizer.EnsureCodePagesRegistered();
        return Encoding.GetEncoding(1251).GetString(bytes);
    }

    public static IReadOnlyList<RegExportKey> Parse(string content)
    {
        var keys = new List<RegExportKey>();
        RegExportKey? current = null;

        foreach (var line in JoinContinuedLines(content))
        {
            var text = line.Trim();
            if (text.Length == 0 || text.StartsWith(';'))
            {
                continue;
            }

            if (text.StartsWith('[') && text.EndsWith(']'))
            {
                current = new RegExportKey { Path = text[1..^1].Trim() };
                keys.Add(current);
                continue;
            }

            if (current is null)
            {
                continue;
            }

            var separator = FindValueSeparator(text);
            if (separator < 0)
            {
                continue;
            }

            var rawName = text[..separator].Trim();
            var name = rawName == "@" ? "" : Unescape(rawName.Trim('"'));
            current.Values[name] = ParseValue(text[(separator + 1)..].Trim());
        }

        return keys;
    }

    /// <summary>
    /// Двоичные значения regedit переносит на несколько строк, заканчивая каждую
    /// обратной косой чертой. Без склейки читается только первая строка, и
    /// длинные значения — например пути устройств в MountedDevices — теряются.
    /// </summary>
    private static IEnumerable<string> JoinContinuedLines(string content)
    {
        var builder = new StringBuilder();
        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (line.TrimEnd().EndsWith('\\'))
            {
                builder.Append(line.TrimEnd().TrimEnd('\\').Trim());
                continue;
            }

            if (builder.Length > 0)
            {
                builder.Append(line.Trim());
                yield return builder.ToString();
                builder.Clear();
                continue;
            }

            yield return line;
        }

        if (builder.Length > 0)
        {
            yield return builder.ToString();
        }
    }

    /// <summary>
    /// Имя значения берётся в кавычки и само может содержать знак равенства,
    /// поэтому разделитель ищется за закрывающей кавычкой.
    /// </summary>
    private static int FindValueSeparator(string text)
    {
        if (text.StartsWith('@'))
        {
            return text.IndexOf('=');
        }

        if (!text.StartsWith('"'))
        {
            return -1;
        }

        for (var i = 1; i < text.Length; i++)
        {
            if (text[i] == '\\')
            {
                i++;
                continue;
            }

            if (text[i] == '"')
            {
                var separator = text.IndexOf('=', i);
                return separator;
            }
        }

        return -1;
    }

    private static object? ParseValue(string text)
    {
        if (text.Equals("-", StringComparison.Ordinal))
        {
            return null;
        }

        if (text.StartsWith('"'))
        {
            var body = text.Length >= 2 && text.EndsWith('"') ? text[1..^1] : text[1..];
            return Unescape(body);
        }

        if (text.StartsWith("dword:", StringComparison.OrdinalIgnoreCase))
        {
            return uint.TryParse(text[6..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value)
                ? value
                : null;
        }

        if (text.StartsWith("hex(b):", StringComparison.OrdinalIgnoreCase))
        {
            var bytes = ParseHexBytes(text[7..]);
            return bytes.Length >= 8 ? BitConverter.ToUInt64(bytes, 0) : bytes;
        }

        if (text.StartsWith("hex(2):", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("hex(1):", StringComparison.OrdinalIgnoreCase))
        {
            return Encoding.Unicode.GetString(ParseHexBytes(text[7..])).TrimEnd('\0');
        }

        if (text.StartsWith("hex(7):", StringComparison.OrdinalIgnoreCase))
        {
            return Encoding.Unicode.GetString(ParseHexBytes(text[7..]))
                .Split('\0', StringSplitOptions.RemoveEmptyEntries);
        }

        if (text.StartsWith("hex(4):", StringComparison.OrdinalIgnoreCase))
        {
            var bytes = ParseHexBytes(text[7..]);
            return bytes.Length >= 4 ? BitConverter.ToUInt32(bytes, 0) : bytes;
        }

        if (text.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
        {
            return ParseHexBytes(text[4..]);
        }

        if (text.StartsWith("hex(", StringComparison.OrdinalIgnoreCase))
        {
            var colon = text.IndexOf(':');
            return colon > 0 ? ParseHexBytes(text[(colon + 1)..]) : Array.Empty<byte>();
        }

        return text;
    }

    /// <summary>
    /// Regedit удваивает обратную косую черту и экранирует кавычки. Без обратного
    /// преобразования имя значения \DosDevices\E: остаётся с двойными косыми и
    /// не совпадает ни с одним ключом при сопоставлении.
    /// </summary>
    private static string Unescape(string value)
    {
        var builder = new StringBuilder(value.Length);
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\' && i + 1 < value.Length && value[i + 1] is '\\' or '"')
            {
                builder.Append(value[i + 1]);
                i++;
                continue;
            }

            builder.Append(value[i]);
        }

        return builder.ToString();
    }

    private static byte[] ParseHexBytes(string text)
    {
        var parts = text.Split(',', StringSplitOptions.RemoveEmptyEntries);
        var bytes = new List<byte>(parts.Length);
        foreach (var part in parts)
        {
            var token = part.Trim();
            if (token.Length > 0
                && byte.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
            {
                bytes.Add(value);
            }
        }

        return [.. bytes];
    }
}
