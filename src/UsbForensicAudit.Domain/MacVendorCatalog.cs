using System.Reflection;
using System.Text;

namespace UsbForensicAudit;

/// <summary>
/// Кто сделал сетевую часть устройства — по началу его аппаратного адреса.
/// Пока сосед по сети не назвал своего имени, это единственное, что о нём
/// известно: «Apple», «TP-LINK», «Hikvision». Для человека, который смотрит
/// список устройств в своей сети, разница между «неизвестное устройство» и
/// «камера Hikvision» решает всё.
///
/// Разбираются три длины префикса. Крупным изготовителям выдают блок из
/// 24 бит целиком, мелким — только часть блока: 28 или 36 бит. Искать надо от
/// длинного к короткому, иначе весь блок достанется его владельцу, а не тому,
/// кому он передал часть адресов.
///
/// База встроена в программу и в сеть за ней не ходит: аудит должен работать
/// на машине без интернета, а результат — не зависеть от того, что сегодня
/// отвечает чужой сервер.
/// </summary>
public static class MacVendorCatalog
{
    private const string EmbeddedResourceName = "UsbForensicAudit.Assets.MacVendors.txt";
    private static readonly int[] PrefixLengths = [9, 7, 6];

    private static readonly Lazy<IReadOnlyDictionary<string, string>> Prefixes = new(Load);

    public static int Count => Prefixes.Value.Count;

    /// <summary>
    /// Название изготовителя или пустая строка, если префикс неизвестен.
    /// Выдумывать название нельзя: в отчёте оно читается как установленный факт.
    /// </summary>
    public static string Lookup(string? macAddress)
    {
        var digits = HexDigits(macAddress);
        if (digits.Length < 6)
        {
            return "";
        }

        foreach (var length in PrefixLengths)
        {
            if (digits.Length >= length
                && Prefixes.Value.TryGetValue(digits[..length], out var vendor))
            {
                return vendor;
            }
        }

        return "";
    }

    /// <summary>
    /// Изготовитель словами, вместе с объяснением, почему его нет. Случайный
    /// адрес телефона не принадлежит никакому заводу, и «изготовитель
    /// неизвестен» в этом случае вводит в заблуждение.
    /// </summary>
    public static string Describe(string? macAddress)
    {
        if (MacAddress.IsEmpty(macAddress))
        {
            return "аппаратный адрес неизвестен";
        }

        var vendor = Lookup(macAddress);
        if (vendor.Length > 0)
        {
            return vendor;
        }

        return MacAddress.IsLocallyAssigned(macAddress)
            ? "адрес назначен на месте, а не заводом — изготовителя по нему не узнать"
            : "изготовитель не найден в базе префиксов";
    }

    public static IReadOnlyDictionary<string, string> Parse(TextReader reader)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        while (reader.ReadLine() is { } line)
        {
            var text = line.Trim();
            if (text.Length == 0 || text[0] == '#')
            {
                continue;
            }

            var separator = text.IndexOf('\t');
            if (separator <= 0)
            {
                continue;
            }

            var prefix = HexDigits(text[..separator]);
            var name = text[(separator + 1)..].Trim();
            if (name.Length == 0 || !PrefixLengths.Contains(prefix.Length))
            {
                continue;
            }

            result.TryAdd(prefix, name);
        }

        return result;
    }

    private static IReadOnlyDictionary<string, string> Load()
    {
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream(EmbeddedResourceName);
            if (stream is null)
            {
                return new Dictionary<string, string>(StringComparer.Ordinal);
            }

            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return Parse(reader);
        }
        catch (Exception)
        {
            // Без базы программа обязана работать: строка «изготовитель не
            // найден» честнее, чем отказ показать найденные устройства.
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }
    }

    /// <summary>
    /// Только шестнадцатеричные знаки, в верхнем регистре: запись префикса
    /// встречается и как «00:1A:2B», и как «001A2B/28».
    /// </summary>
    private static string HexDigits(string? value)
    {
        var builder = new StringBuilder(12);
        foreach (var ch in value ?? "")
        {
            if (ch == '/')
            {
                break;
            }

            if (Uri.IsHexDigit(ch))
            {
                builder.Append(char.ToUpperInvariant(ch));
            }
        }

        return builder.ToString();
    }
}
