using System.Net;
using System.Text;

namespace UsbForensicAudit;

/// <summary>
/// Пакеты mDNS (RFC 6762): обратный вопрос «как зовут устройство с этим
/// адресом» на порт UDP 5353. Так своё имя отдают телефоны, принтеры и
/// техника Apple/Android — те, кто молчит и на DNS, и на NetBIOS.
/// </summary>
public static class MulticastDnsProtocol
{
    /// <summary>Порт mDNS.</summary>
    public const int Port = 5353;

    /// <summary>
    /// Обратный вопрос PTR для адреса IPv4: «1.2.168.192.in-addr.arpa».
    /// Ставится бит QU — «ответь мне напрямую, а не всей сети».
    /// </summary>
    public static byte[] BuildReversePtrQuery(string ipAddress, ushort transactionId)
    {
        if (!IPAddress.TryParse(ipAddress, out var parsed)
            || parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return [];
        }

        var bytes = parsed.GetAddressBytes();
        var name = $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}.in-addr.arpa";
        var labels = name.Split('.');

        var packet = new List<byte>(64)
        {
            (byte)(transactionId >> 8), (byte)transactionId,
            0x00, 0x00, // флаги: обычный запрос
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        foreach (var label in labels)
        {
            var encoded = Encoding.ASCII.GetBytes(label);
            packet.Add((byte)encoded.Length);
            packet.AddRange(encoded);
        }

        packet.Add(0x00);
        packet.Add(0x00);
        packet.Add(0x0C); // QTYPE = PTR
        packet.Add(0x80); // QCLASS = IN + бит QU (unicast response)
        packet.Add(0x01);
        return [.. packet];
    }

    /// <summary>
    /// Достаёт имя из первой записи PTR ответа. Хвост «.local» отрезается:
    /// в таблице он только мешает читать. Пустая строка — ответ не разобран.
    /// </summary>
    public static string ParsePtrResponse(ReadOnlySpan<byte> response, ushort expectedTransactionId)
    {
        if (response.Length < 12)
        {
            return "";
        }

        var transactionId = (ushort)((response[0] << 8) | response[1]);
        var isResponse = (response[2] & 0x80) != 0;
        // mDNS-ответчики часто ставят transaction id = 0 — это допустимо.
        if (!isResponse || (transactionId != expectedTransactionId && transactionId != 0))
        {
            return "";
        }

        int questions = (response[4] << 8) | response[5];
        int answers = (response[6] << 8) | response[7];
        if (answers == 0)
        {
            return "";
        }

        var offset = 12;
        for (var index = 0; index < questions; index++)
        {
            offset = SkipName(response, offset);
            offset += 4; // QTYPE + QCLASS
            if (offset < 0 || offset > response.Length)
            {
                return "";
            }
        }

        for (var index = 0; index < answers; index++)
        {
            offset = SkipName(response, offset);
            if (offset < 0 || offset + 10 > response.Length)
            {
                return "";
            }

            var type = (response[offset] << 8) | response[offset + 1];
            var dataLength = (response[offset + 8] << 8) | response[offset + 9];
            offset += 10;
            if (offset + dataLength > response.Length)
            {
                return "";
            }

            if (type == 0x0C)
            {
                var name = ReadName(response, offset);
                if (name.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
                {
                    name = name[..^".local".Length];
                }

                return name;
            }

            offset += dataLength;
        }

        return "";
    }

    private static int SkipName(ReadOnlySpan<byte> data, int offset)
    {
        while (offset < data.Length)
        {
            var length = data[offset];
            if (length == 0)
            {
                return offset + 1;
            }

            if ((length & 0xC0) == 0xC0)
            {
                return offset + 2; // указатель сжатия завершает имя
            }

            offset += length + 1;
        }

        return -1;
    }

    private static string ReadName(ReadOnlySpan<byte> data, int offset)
    {
        var parts = new List<string>();
        var jumps = 0;
        while (offset >= 0 && offset < data.Length && jumps < 16)
        {
            var length = data[offset];
            if (length == 0)
            {
                break;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (offset + 1 >= data.Length)
                {
                    break;
                }

                offset = ((length & 0x3F) << 8) | data[offset + 1];
                jumps++;
                continue;
            }

            if (offset + 1 + length > data.Length)
            {
                break;
            }

            parts.Add(Encoding.UTF8.GetString(data.Slice(offset + 1, length)));
            offset += length + 1;
        }

        return string.Join(".", parts);
    }
}
