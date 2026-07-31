using System.Globalization;
using System.Net;

namespace UsbForensicAudit;

/// <summary>
/// Разбор значений, которыми журналы Windows описывают сетевые соединения:
/// двоичный адрес удалённой стороны и код завершения операции.
/// </summary>
internal static class NetworkEventValues
{
    private const int AddressFamilyIpV4 = 2;
    private const int AddressFamilyIpV6 = 23;

    /// <summary>
    /// Адрес удалённой стороны журнал SMB пишет не текстом, а шестнадцатеричной
    /// строкой структуры sockaddr: «170001BD…» — это семейство адресов 23 (IPv6),
    /// порт 445 и сам адрес. Без разбора в отчёте вместо «20.20.20.76» стояла бы
    /// эта строка, по которой ничего не понять.
    /// </summary>
    internal static bool TryReadSocketAddress(string? hex, out string address, out int port)
    {
        address = "";
        port = 0;

        var text = (hex ?? "").Trim();
        if (text.Length < 16 || text.Length % 2 != 0 || !IsHex(text))
        {
            return false;
        }

        var bytes = Convert.FromHexString(text);
        var family = BitConverter.ToUInt16(bytes, 0);
        port = (bytes[2] << 8) | bytes[3];

        var (offset, length) = family switch
        {
            AddressFamilyIpV4 => (4, 4),
            AddressFamilyIpV6 => (8, 16),
            _ => (0, 0)
        };

        if (length == 0 || bytes.Length < offset + length)
        {
            return false;
        }

        var parsed = new IPAddress(bytes.AsSpan(offset, length).ToArray());

        // Адрес IPv4, завёрнутый в IPv6 («::ffff:20.20.20.76»), человеку понятнее
        // в своём обычном виде.
        if (parsed.IsIPv4MappedToIPv6)
        {
            parsed = parsed.MapToIPv4();
        }

        address = parsed.ToString();
        return address.Length > 0 && address != "::" && address != "0.0.0.0";
    }

    /// <summary>
    /// Код завершения из журнала SMB словами. Число «3221225506» в отчёте
    /// бесполезно, а «доступ запрещён» отвечает на вопрос, получилось ли открыть
    /// сетевую папку. Незнакомый код остаётся числом в шестнадцатеричном виде:
    /// придумывать ему смысл нельзя.
    /// </summary>
    internal static string DescribeStatus(string? value)
    {
        if (!TryReadStatus(value, out var status))
        {
            return "";
        }

        return status switch
        {
            0x00000000 => "успешно",
            0xC0000022 => "доступ запрещён",
            0xC000006D => "не приняты имя или пароль",
            0xC000006E => "учётная запись не допущена к этому входу",
            0xC0000064 => "такой учётной записи нет",
            0xC000009A => "у сервера не хватило ресурсов",
            0xC00000B5 => "сервер не ответил за отведённое время",
            0xC00000BB => "сервер не поддерживает запрошенную операцию",
            0xC00000CC => "такой сетевой папки на сервере нет",
            0xC000014B => "соединение оборвано",
            0xC0000203 => "сервер закрыл сеанс",
            0xC000023A => "сервер отказал в соединении",
            0xC0000236 => "соединение отклонено сервером",
            0xC0000241 => "соединение прервано",
            0x80000016 => "устройство не готово",
            _ => $"код 0x{status:X8}"
        };
    }

    private static bool TryReadStatus(string? value, out uint status)
    {
        status = 0;
        var text = (value ?? "").Trim();
        if (text.Length == 0)
        {
            return false;
        }

        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return uint.TryParse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out status);
        }

        if (uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out status))
        {
            return true;
        }

        // Windows иногда пишет код со знаком: «-1073741790» — то же значение.
        if (int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var signed))
        {
            status = unchecked((uint)signed);
            return true;
        }

        return false;
    }

    private static bool IsHex(string text) => text.All(Uri.IsHexDigit);
}
