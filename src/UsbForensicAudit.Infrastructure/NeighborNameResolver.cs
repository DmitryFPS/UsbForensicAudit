using System.Net;
using System.Net.Sockets;

namespace UsbForensicAudit;

/// <summary>
/// Спрашивает у устройства его имя напрямую, минуя DNS: по NetBIOS (порт 137,
/// так отвечают машины Windows и NAS) и по mDNS (порт 5353, так отвечают
/// телефоны, принтеры и техника Apple). Ошибки здесь — норма: большинство
/// устройств молчит, и молчание не событие.
/// </summary>
internal static class NeighborNameResolver
{
    private const int ReplyTimeoutMs = 700;

    /// <summary>Имя по NetBIOS Node Status или пустая строка.</summary>
    public static async Task<string> TryNetbiosAsync(string ipAddress, CancellationToken cancellationToken)
    {
        var transactionId = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        var request = NetbiosNameProtocol.BuildNodeStatusRequest(transactionId);
        var response = await ExchangeUdpAsync(
            ipAddress, NetbiosNameProtocol.Port, request, cancellationToken).ConfigureAwait(false);
        return response.Length > 0
            ? NetbiosNameProtocol.ParseNodeStatusResponse(response, transactionId)
            : "";
    }

    /// <summary>Имя по обратному вопросу mDNS или пустая строка.</summary>
    public static async Task<string> TryMdnsAsync(string ipAddress, CancellationToken cancellationToken)
    {
        var transactionId = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        var request = MulticastDnsProtocol.BuildReversePtrQuery(ipAddress, transactionId);
        if (request.Length == 0)
        {
            return "";
        }

        var response = await ExchangeUdpAsync(
            ipAddress, MulticastDnsProtocol.Port, request, cancellationToken).ConfigureAwait(false);
        return response.Length > 0
            ? MulticastDnsProtocol.ParsePtrResponse(response, transactionId)
            : "";
    }

    /// <summary>
    /// Один UDP-запрос и один ответ с таймаутом. Пустой массив — устройство
    /// промолчало или отказалось, различать эти случаи не нужно.
    /// </summary>
    private static async Task<byte[]> ExchangeUdpAsync(
        string ipAddress, int port, byte[] request, CancellationToken cancellationToken)
    {
        if (!IPAddress.TryParse(ipAddress, out var target))
        {
            return [];
        }

        try
        {
            using var client = new UdpClient(target.AddressFamily);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(ReplyTimeoutMs);

            await client.SendAsync(request, new IPEndPoint(target, port), timeout.Token).ConfigureAwait(false);
            var result = await client.ReceiveAsync(timeout.Token).ConfigureAwait(false);
            return result.Buffer;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Истёк таймаут ответа — устройство молчит, это норма.
            return [];
        }
        catch (SocketException)
        {
            // Порт закрыт или хост отбил запрос — тоже норма.
            return [];
        }
    }
}
