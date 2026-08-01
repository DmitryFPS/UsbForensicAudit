using System.Text;

namespace UsbForensicAudit;

/// <summary>
/// Пакеты NetBIOS Node Status (RFC 1002): вопрос «как тебя зовут» на порт
/// UDP 137 и разбор ответа. Так своё имя отдают машины Windows и NAS, даже
/// когда обратная запись DNS для них не заведена.
/// </summary>
public static class NetbiosNameProtocol
{
    /// <summary>Порт службы имён NetBIOS.</summary>
    public const int Port = 137;

    private const byte WildcardNameLength = 0x20;
    private const int HeaderLength = 12;

    /// <summary>
    /// Запрос Node Status на «любое имя» (имя «*»). Устройство в ответ
    /// перечисляет все свои имена NetBIOS.
    /// </summary>
    public static byte[] BuildNodeStatusRequest(ushort transactionId)
    {
        var packet = new byte[50];
        packet[0] = (byte)(transactionId >> 8);
        packet[1] = (byte)transactionId;
        // Flags = 0x0000 (запрос), QDCOUNT = 1.
        packet[5] = 1;
        packet[HeaderLength] = WildcardNameLength;
        // Имя «*» дополняется нулями до 16 байт и кодируется полубайтами:
        // каждый полубайт превращается в букву 'A'..'P'.
        var raw = new byte[16];
        raw[0] = (byte)'*';
        for (var index = 0; index < raw.Length; index++)
        {
            packet[HeaderLength + 1 + index * 2] = (byte)('A' + (raw[index] >> 4));
            packet[HeaderLength + 2 + index * 2] = (byte)('A' + (raw[index] & 0x0F));
        }

        // Терминатор имени, затем QTYPE = NBSTAT (0x0021), QCLASS = IN (0x0001).
        packet[45] = 0x00;
        packet[46] = 0x00;
        packet[47] = 0x21;
        packet[48] = 0x00;
        packet[49] = 0x01;
        return packet;
    }

    /// <summary>
    /// Достаёт из ответа Node Status первое уникальное имя машины
    /// (суффиксы 0x00 «рабочая станция» и 0x20 «файловая служба»).
    /// Возвращает пустую строку, если ответ не похож на правду.
    /// </summary>
    public static string ParseNodeStatusResponse(ReadOnlySpan<byte> response, ushort expectedTransactionId)
    {
        // Заголовок + закодированное имя (34) + тип/класс (4) + TTL (4) + RDLENGTH (2) + счётчик имён (1).
        const int nameCountOffset = HeaderLength + 34 + 4 + 4 + 2;
        if (response.Length < nameCountOffset + 1)
        {
            return "";
        }

        var transactionId = (ushort)((response[0] << 8) | response[1]);
        var isResponse = (response[2] & 0x80) != 0;
        if (transactionId != expectedTransactionId || !isResponse)
        {
            return "";
        }

        int nameCount = response[nameCountOffset];
        var offset = nameCountOffset + 1;
        var fallback = "";
        for (var index = 0; index < nameCount; index++)
        {
            var entry = offset + index * 18;
            if (entry + 18 > response.Length)
            {
                break;
            }

            var name = Encoding.ASCII.GetString(response.Slice(entry, 15)).TrimEnd(' ', '\0');
            var suffix = response[entry + 16 - 1];
            var flags = (ushort)((response[entry + 16] << 8) | response[entry + 17]);
            var isGroup = (flags & 0x8000) != 0;
            if (name.Length == 0 || isGroup || name.StartsWith("\u0001\u0002", StringComparison.Ordinal))
            {
                continue;
            }

            if (suffix == 0x00)
            {
                return name;
            }

            if (fallback.Length == 0 && suffix == 0x20)
            {
                fallback = name;
            }
        }

        return fallback;
    }
}
