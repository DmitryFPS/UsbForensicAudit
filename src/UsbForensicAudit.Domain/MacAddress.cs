using System.Text;

namespace UsbForensicAudit;

/// <summary>
/// Аппаратный адрес устройства в сети. Нужен здесь по двум причинам.
///
/// По первым трём байтам видно, кто сделал сетевую часть устройства: у Apple
/// свои префиксы, у TP-Link свои. Это единственное, что говорит о железе
/// соседа по сети, пока он сам не назвался.
///
/// Второй бит первого байта означает, что адрес выдан не заводом, а назначен
/// на месте. Телефоны с Android и iOS так прячутся: каждой сети они называют
/// новый случайный адрес. Такой адрес нельзя использовать как опознаватель
/// устройства — в другой раз тот же телефон придёт под другим.
/// </summary>
public static class MacAddress
{
    /// <summary>Единый вид адреса: «88:75:98:C2:F5:F2». Пустая строка, если адреса нет.</summary>
    public static string Normalize(string? value)
    {
        var digits = new StringBuilder(12);
        foreach (var ch in value ?? "")
        {
            if (Uri.IsHexDigit(ch))
            {
                digits.Append(char.ToUpperInvariant(ch));
            }
        }

        if (digits.Length != 12)
        {
            return "";
        }

        var builder = new StringBuilder(17);
        for (var index = 0; index < 12; index += 2)
        {
            if (index > 0)
            {
                builder.Append(':');
            }

            builder.Append(digits[index]).Append(digits[index + 1]);
        }

        return builder.ToString();
    }

    public static string Format(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0)
        {
            return "";
        }

        var builder = new StringBuilder(bytes.Length * 3);
        foreach (var value in bytes)
        {
            if (builder.Length > 0)
            {
                builder.Append(':');
            }

            builder.Append(value.ToString("X2"));
        }

        return builder.ToString();
    }

    /// <summary>Первые три байта — префикс завода-изготовителя.</summary>
    public static string OrganizationPrefix(string? value)
    {
        var normalized = Normalize(value);
        return normalized.Length == 17 ? normalized[..8] : "";
    }

    /// <summary>
    /// Адрес назначен на месте, а не выдан заводом. У телефонов это защита от
    /// слежки: устройство называет каждой сети новый адрес.
    /// </summary>
    public static bool IsLocallyAssigned(string? value)
    {
        var normalized = Normalize(value);
        return normalized.Length == 17
               && byte.TryParse(normalized[..2], System.Globalization.NumberStyles.HexNumber, null, out var first)
               && (first & 0x02) != 0;
    }

    /// <summary>Адрес не одного устройства, а рассылки сразу многим.</summary>
    public static bool IsGroup(string? value)
    {
        var normalized = Normalize(value);
        return normalized.Length == 17
               && byte.TryParse(normalized[..2], System.Globalization.NumberStyles.HexNumber, null, out var first)
               && (first & 0x01) != 0;
    }

    public static bool IsEmpty(string? value) => Normalize(value).Length == 0;
}
