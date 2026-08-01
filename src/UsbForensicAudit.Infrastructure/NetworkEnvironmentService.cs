using System.Net;
using System.Net.NetworkInformation;
using System.Numerics;
using System.Runtime.InteropServices;

namespace UsbForensicAudit;

/// <summary>
/// Снимает обстановку вокруг машины: сети Wi-Fi в эфире и устройства в текущей
/// сети. Это состояние «сейчас», а не история подключений из реестра.
/// </summary>
public sealed class NetworkEnvironmentService : INetworkEnvironmentService
{
    private const int MaxProbeHosts = 254;
    private const int ProbeTimeoutMs = 400;
    private const int WlanScanWaitMs = 2500;

    public async Task<NetworkEnvironmentSnapshot> CaptureAsync(
        bool activeProbe,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var snapshot = new NetworkEnvironmentSnapshot
        {
            TakenAtUtc = DateTimeOffset.UtcNow,
            ActiveProbeUsed = activeProbe
        };

        progress?.Report("Сканирую Wi-Fi в эфире...");
        List<WirelessNetworkRecord> wireless;
        try
        {
            wireless = await ScanWirelessNetworksAsync(snapshot.Warnings, cancellationToken).ConfigureAwait(false);
            snapshot.WirelessNetworks.AddRange(wireless);
        }
        catch (Exception ex)
        {
            snapshot.Warnings.Add($"Wi-Fi: {ex.Message}");
            wireless = [];
        }

        progress?.Report("Читаю сетевые адаптеры...");
        snapshot.Adapters.AddRange(ReadAdapters(wireless));

        cancellationToken.ThrowIfCancellationRequested();

        progress?.Report(activeProbe
            ? "Ищу устройства в сети: таблица соседей и опрос подсети..."
            : "Ищу устройства в сети: только таблица соседей Windows...");
        snapshot.Neighbors.AddRange(await CollectNeighborsAsync(
            snapshot.Adapters, activeProbe, snapshot, progress, cancellationToken).ConfigureAwait(false));

        progress?.Report("Готово.");
        return snapshot;
    }

    private static List<NetworkAdapterRecord> ReadAdapters(IReadOnlyList<WirelessNetworkRecord> wireless)
    {
        var result = new List<NetworkAdapterRecord>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                     .Where(x => x.OperationalStatus == OperationalStatus.Up))
        {
            var props = nic.GetIPProperties();
            var ipv4 = props.UnicastAddresses
                .FirstOrDefault(x => x.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            if (ipv4 is null)
            {
                continue;
            }

            var gateways = props.GatewayAddresses
                .Select(x => x.Address.ToString())
                .Where(x => x != "0.0.0.0")
                .ToList();
            var dns = props.DnsAddresses
                .Where(x => x.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                .Select(x => x.ToString())
                .ToList();
            var dhcpEntry = props.DhcpServerAddresses
                .FirstOrDefault(x => x.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var dhcp = dhcpEntry?.ToString() ?? "";

            var kind = nic.NetworkInterfaceType switch
            {
                NetworkInterfaceType.Wireless80211 => NetworkConnectionKind.WiFi,
                NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet => NetworkConnectionKind.Wired,
                NetworkInterfaceType.Ppp => NetworkConnectionKind.Vpn,
                _ => NetworkConnectionKind.Unknown
            };

            var connectedSsid = kind == NetworkConnectionKind.WiFi
                ? wireless.FirstOrDefault(x => x.IsConnected
                    && x.Adapter.Equals(nic.Description, StringComparison.OrdinalIgnoreCase))?.Ssid ?? ""
                : "";

            result.Add(new NetworkAdapterRecord
            {
                Name = nic.Name,
                Description = nic.Description,
                MacAddress = MacAddress.Normalize(nic.GetPhysicalAddress().ToString()),
                Kind = kind,
                ConnectedSsid = connectedSsid,
                Addresses = [ipv4.Address.ToString()],
                Gateways = gateways,
                DnsServers = dns,
                DhcpServer = dhcp,
                Subnet = BuildSubnet(ipv4.Address, ipv4.IPv4Mask)
            });
        }

        return result;
    }

    private static string BuildSubnet(IPAddress address, IPAddress? mask)
    {
        if (mask is null || mask.GetAddressBytes().All(x => x == 0))
        {
            return "";
        }

        var ip = address.GetAddressBytes();
        var net = mask.GetAddressBytes();
        var network = new byte[4];
        for (var index = 0; index < 4; index++)
        {
            network[index] = (byte)(ip[index] & net[index]);
        }

        var prefix = CountMaskBits(net);
        return $"{new IPAddress(network)}/{prefix}";
    }

    private static int CountMaskBits(byte[] mask)
    {
        var bits = 0;
        foreach (var value in mask)
        {
            bits += BitOperations.PopCount(value);
        }

        return bits;
    }

    private static async Task<List<WirelessNetworkRecord>> ScanWirelessNetworksAsync(
        List<string> warnings, CancellationToken cancellationToken)
    {
        var result = new List<WirelessNetworkRecord>();
        if (WlanApi.WlanOpenHandle(WlanApi.ClientVersionVista, IntPtr.Zero, out _, out var handle) != WlanApi.Success)
        {
            warnings.Add("Служба беспроводных сетей недоступна: Wi-Fi в эфире не прослушан.");
            return result;
        }

        try
        {
            if (WlanApi.WlanEnumInterfaces(handle, IntPtr.Zero, out var listPtr) != WlanApi.Success)
            {
                warnings.Add("Радиомодули Wi-Fi не найдены.");
                return result;
            }

            try
            {
                var count = Marshal.ReadInt32(listPtr);
                var itemSize = Marshal.SizeOf<WlanApi.WlanInterfaceInfo>();
                var offset = 8;
                for (var index = 0; index < count; index++)
                {
                    var info = Marshal.PtrToStructure<WlanApi.WlanInterfaceInfo>(listPtr + offset + index * itemSize);
                    WlanApi.WlanScan(handle, ref info.InterfaceGuid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                }

                await Task.Delay(WlanScanWaitMs, cancellationToken).ConfigureAwait(false);

                for (var index = 0; index < count; index++)
                {
                    var info = Marshal.PtrToStructure<WlanApi.WlanInterfaceInfo>(listPtr + offset + index * itemSize);
                    result.AddRange(ReadNetworksForInterface(handle, info));
                }
            }
            finally
            {
                WlanApi.WlanFreeMemory(listPtr);
            }
        }
        finally
        {
            WlanApi.WlanCloseHandle(handle, IntPtr.Zero);
        }

        return DeduplicateWireless(result);
    }

    private static IEnumerable<WirelessNetworkRecord> ReadNetworksForInterface(
        IntPtr handle, WlanApi.WlanInterfaceInfo info)
    {
        var adapter = info.InterfaceDescription;
        var bssBySsid = ReadBssMap(handle, info.InterfaceGuid);
        if (WlanApi.WlanGetAvailableNetworkList(handle, ref info.InterfaceGuid, 0, IntPtr.Zero, out var netPtr)
            != WlanApi.Success)
        {
            yield break;
        }

        try
        {
            var count = Marshal.ReadInt32(netPtr);
            var itemSize = Marshal.SizeOf<WlanApi.WlanAvailableNetwork>();
            var offset = 8;
            for (var index = 0; index < count; index++)
            {
                var network = Marshal.PtrToStructure<WlanApi.WlanAvailableNetwork>(netPtr + offset + index * itemSize);
                var ssid = ReadSsid(network.Ssid);
                var security = WlanApi.DescribeSecurity(
                    network.SecurityEnabled, network.DefaultAuthAlgorithm, network.DefaultCipherAlgorithm);
                var connected = (network.Flags & WlanApi.NetworkConnected) != 0;
                var hasProfile = (network.Flags & WlanApi.NetworkHasProfile) != 0;

                if (bssBySsid.TryGetValue(ssid, out var bssList) && bssList.Count > 0)
                {
                    foreach (var bss in bssList)
                    {
                        yield return new WirelessNetworkRecord
                        {
                            Ssid = ssid,
                            Bssid = bss.Bssid,
                            Security = security,
                            SignalPercent = bss.SignalPercent,
                            Channel = bss.Channel,
                            Band = bss.Band,
                            IsConnected = connected,
                            HasSavedProfile = hasProfile || network.ProfileName.Length > 0,
                            Adapter = adapter,
                            SeenAtUtc = DateTimeOffset.UtcNow
                        };
                    }
                }
                else
                {
                    yield return new WirelessNetworkRecord
                    {
                        Ssid = ssid,
                        Security = security,
                        SignalPercent = (int)network.SignalQuality,
                        IsConnected = connected,
                        HasSavedProfile = hasProfile || network.ProfileName.Length > 0,
                        Adapter = adapter,
                        SeenAtUtc = DateTimeOffset.UtcNow
                    };
                }
            }
        }
        finally
        {
            WlanApi.WlanFreeMemory(netPtr);
        }
    }

    private static Dictionary<string, List<(string Bssid, int SignalPercent, int Channel, string Band)>> ReadBssMap(
        IntPtr handle, Guid interfaceGuid)
    {
        var result = new Dictionary<string, List<(string, int, int, string)>>(StringComparer.Ordinal);
        if (WlanApi.WlanGetNetworkBssList(
                handle, ref interfaceGuid, IntPtr.Zero, WlanApi.WlanBssType.Any, false, IntPtr.Zero, out var bssPtr)
            != WlanApi.Success)
        {
            return result;
        }

        try
        {
            var count = Marshal.ReadInt32(bssPtr, 4);
            var itemSize = Marshal.SizeOf<WlanApi.WlanBssEntry>();
            var offset = 8;
            for (var index = 0; index < count; index++)
            {
                var entry = Marshal.PtrToStructure<WlanApi.WlanBssEntry>(bssPtr + offset + index * itemSize);
                var ssid = ReadSsid(entry.Ssid);
                var bssid = MacAddress.Format(entry.Bssid);
                var (channel, band) = WlanApi.ReadChannel(entry.ChCenterFrequency);
                var signal = entry.LinkQuality > 0
                    ? (int)entry.LinkQuality
                    : WlanApi.SignalPercent(entry.Rssi);
                if (!result.TryGetValue(ssid, out var list))
                {
                    list = [];
                    result[ssid] = list;
                }

                list.Add((bssid, signal, channel, band));
            }
        }
        finally
        {
            WlanApi.WlanFreeMemory(bssPtr);
        }

        return result;
    }

    private static string ReadSsid(WlanApi.Dot11Ssid ssid)
    {
        if (ssid.Ssid is null || ssid.SsidLength == 0)
        {
            return "";
        }

        return System.Text.Encoding.UTF8.GetString(ssid.Ssid, 0, (int)Math.Min(ssid.SsidLength, ssid.Ssid.Length));
    }

    private static List<WirelessNetworkRecord> DeduplicateWireless(IEnumerable<WirelessNetworkRecord> networks) =>
        networks
            .GroupBy(x => $"{x.Ssid}|{x.Bssid}|{x.Adapter}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.SignalPercent).First())
            .OrderByDescending(x => x.IsConnected)
            .ThenByDescending(x => x.HasSavedProfile)
            .ThenByDescending(x => x.SignalPercent)
            .ThenBy(x => x.Ssid, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static async Task<List<NetworkNeighborRecord>> CollectNeighborsAsync(
        IReadOnlyList<NetworkAdapterRecord> adapters,
        bool activeProbe,
        NetworkEnvironmentSnapshot snapshot,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        var seenAt = DateTimeOffset.UtcNow;
        var neighbors = new Dictionary<string, NetworkNeighborRecord>(StringComparer.OrdinalIgnoreCase);
        var networkLabel = adapters.FirstOrDefault(x => x.Kind == NetworkConnectionKind.WiFi)?.ConnectedSsid
                           ?? adapters.FirstOrDefault()?.Subnet
                           ?? "текущая сеть";

        foreach (var adapter in adapters)
        {
            AddConfiguredRoles(neighbors, adapter, networkLabel, seenAt);
        }

        foreach (var arp in IpHelperApi.ReadArpTable())
        {
            AddNeighbor(neighbors, new NetworkNeighborRecord
            {
                IpAddress = arp.IpAddress,
                MacAddress = arp.MacAddress,
                Role = ClassifyRole(arp.IpAddress, adapters),
                Discovery = NeighborDiscovery.NeighborTable,
                State = arp.State,
                Network = networkLabel,
                SeenAtUtc = seenAt
            });
        }

        if (activeProbe)
        {
            var targets = BuildProbeTargets(adapters).Take(MaxProbeHosts).ToList();
            snapshot.ProbedAddresses = targets.Count;
            // Параллельные задачи только опрашивают и возвращают находки:
            // общий словарь соседей — обычный Dictionary, и трогать его из
            // нескольких потоков нельзя. Склейка идёт после Task.WhenAll,
            // уже в одном потоке.
            var gate = new SemaphoreSlim(32);
            var tasks = targets.Select(async ip =>
            {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    using var ping = new Ping();
                    var reply = await ping.SendPingAsync(ip, ProbeTimeoutMs).ConfigureAwait(false);
                    if (reply.Status != IPStatus.Success)
                    {
                        return null;
                    }

                    var mac = IpHelperApi.TryResolveMac(ip) ?? "";
                    return new NetworkNeighborRecord
                    {
                        IpAddress = ip,
                        MacAddress = mac,
                        Role = ClassifyRole(ip, adapters),
                        Discovery = NeighborDiscovery.ActiveProbe,
                        State = "ответил на опрос",
                        Network = networkLabel,
                        SeenAtUtc = seenAt
                    };
                }
                catch (PingException)
                {
                    // Молчащий хост — норма.
                    return null;
                }
                finally
                {
                    gate.Release();
                }
            });
            var probed = await Task.WhenAll(tasks).ConfigureAwait(false);
            foreach (var record in probed)
            {
                if (record is not null)
                {
                    AddNeighbor(neighbors, record);
                }
            }
        }

        await ResolveNamesAsync(neighbors.Values, progress, cancellationToken).ConfigureAwait(false);
        return neighbors.Values
            .OrderBy(x => NeighborRole.Rank(x.Role))
            .ThenBy(x => IpToSortable(x.IpAddress))
            .ToList();
    }

    private static void AddConfiguredRoles(
        Dictionary<string, NetworkNeighborRecord> neighbors,
        NetworkAdapterRecord adapter,
        string networkLabel,
        DateTimeOffset seenAt)
    {
        foreach (var ip in adapter.Addresses)
        {
            AddNeighbor(neighbors, new NetworkNeighborRecord
            {
                IpAddress = ip,
                MacAddress = adapter.MacAddress,
                Role = NeighborRole.ThisMachine,
                Discovery = NeighborDiscovery.Configuration,
                State = "эта машина",
                Adapter = adapter.Description,
                Network = networkLabel,
                SeenAtUtc = seenAt
            });
        }

        foreach (var ip in adapter.Gateways)
        {
            AddNeighbor(neighbors, new NetworkNeighborRecord
            {
                IpAddress = ip,
                MacAddress = IpHelperApi.TryResolveMac(ip) ?? "",
                Role = NeighborRole.Gateway,
                Discovery = NeighborDiscovery.Configuration,
                State = "из настроек адаптера",
                Adapter = adapter.Description,
                Network = networkLabel,
                SeenAtUtc = seenAt
            });
        }

        if (adapter.DhcpServer.Length > 0)
        {
            AddNeighbor(neighbors, new NetworkNeighborRecord
            {
                IpAddress = adapter.DhcpServer,
                MacAddress = IpHelperApi.TryResolveMac(adapter.DhcpServer) ?? "",
                Role = NeighborRole.DhcpServer,
                Discovery = NeighborDiscovery.Configuration,
                State = "из настроек адаптера",
                Adapter = adapter.Description,
                Network = networkLabel,
                SeenAtUtc = seenAt
            });
        }

        foreach (var ip in adapter.DnsServers)
        {
            AddNeighbor(neighbors, new NetworkNeighborRecord
            {
                IpAddress = ip,
                MacAddress = IpHelperApi.TryResolveMac(ip) ?? "",
                Role = NeighborRole.DnsServer,
                Discovery = NeighborDiscovery.Configuration,
                State = "из настроек адаптера",
                Adapter = adapter.Description,
                Network = networkLabel,
                SeenAtUtc = seenAt
            });
        }
    }

    private static void AddNeighbor(Dictionary<string, NetworkNeighborRecord> neighbors, NetworkNeighborRecord candidate)
    {
        var key = candidate.IpAddress.Length > 0
            ? candidate.IpAddress
            : candidate.MacAddress;
        if (key.Length == 0)
        {
            return;
        }

        if (!neighbors.TryGetValue(key, out var existing))
        {
            neighbors[key] = candidate;
            return;
        }

        if (existing.MacAddress.Length == 0 && candidate.MacAddress.Length > 0)
        {
            existing.MacAddress = candidate.MacAddress;
        }

        if (existing.HostName.Length == 0 && candidate.HostName.Length > 0)
        {
            existing.HostName = candidate.HostName;
        }

        if (NeighborRole.Rank(candidate.Role) < NeighborRole.Rank(existing.Role))
        {
            existing.Role = candidate.Role;
        }

        if (existing.State.Length == 0)
        {
            existing.State = candidate.State;
        }

        if (existing.Adapter.Length == 0)
        {
            existing.Adapter = candidate.Adapter;
        }
    }

    private static string ClassifyRole(string ip, IReadOnlyList<NetworkAdapterRecord> adapters)
    {
        foreach (var adapter in adapters)
        {
            if (adapter.Addresses.Contains(ip, StringComparer.OrdinalIgnoreCase))
            {
                return NeighborRole.ThisMachine;
            }

            if (adapter.Gateways.Contains(ip, StringComparer.OrdinalIgnoreCase))
            {
                return NeighborRole.Gateway;
            }

            if (adapter.DhcpServer.Equals(ip, StringComparison.OrdinalIgnoreCase))
            {
                return NeighborRole.DhcpServer;
            }

            if (adapter.DnsServers.Contains(ip, StringComparer.OrdinalIgnoreCase))
            {
                return NeighborRole.DnsServer;
            }
        }

        return NeighborRole.Neighbor;
    }

    private static IEnumerable<string> BuildProbeTargets(IReadOnlyList<NetworkAdapterRecord> adapters)
    {
        foreach (var adapter in adapters)
        {
            if (adapter.Subnet.Length == 0 || adapter.Addresses.Count == 0)
            {
                continue;
            }

            var parts = adapter.Subnet.Split('/');
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network)
                || !int.TryParse(parts[1], out var prefix) || prefix > 24)
            {
                continue;
            }

            var hostCount = 1 << (32 - prefix);
            if (hostCount <= 2)
            {
                continue;
            }

            var networkBytes = network.GetAddressBytes();
            var baseValue = BitConverter.ToUInt32(networkBytes, 0);
            var own = adapter.Addresses
                .Select(x => IPAddress.TryParse(x, out var parsed) ? BitConverter.ToUInt32(parsed.GetAddressBytes(), 0) : 0u)
                .ToHashSet();

            for (uint offset = 1; offset < hostCount - 1; offset++)
            {
                var value = baseValue + offset;
                if (own.Contains(value))
                {
                    continue;
                }

                yield return new IPAddress(BitConverter.GetBytes(value)).ToString();
            }
        }
    }

    private static async Task ResolveNamesAsync(
        IEnumerable<NetworkNeighborRecord> neighbors,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        var targets = neighbors
            .Where(x => x.Role != NeighborRole.ThisMachine && ShouldResolveName(x.IpAddress))
            .ToList();
        if (targets.Count == 0)
        {
            return;
        }

        progress?.Report($"Спрашиваю имена устройств: 0 из {targets.Count}...");
        var completed = 0;
        var gate = new SemaphoreSlim(8);
        var tasks = targets.Select(async neighbor =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var entry = await Dns.GetHostEntryAsync(neighbor.IpAddress)
                    .WaitAsync(TimeSpan.FromMilliseconds(800), cancellationToken)
                    .ConfigureAwait(false);
                var host = entry.HostName;
                if (host.Length > 0 && !host.Equals(neighbor.IpAddress, StringComparison.OrdinalIgnoreCase))
                {
                    neighbor.HostName = host;
                }
            }
            catch
            {
                // Имя не ответило — норма для телефонов и IoT.
            }
            finally
            {
                gate.Release();
                var done = Interlocked.Increment(ref completed);
                if (done == 1 || done % 5 == 0 || done == targets.Count)
                {
                    progress?.Report($"Спрашиваю имена устройств: {done} из {targets.Count}...");
                }
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private static bool ShouldResolveName(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var parsed)
            || parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = parsed.GetAddressBytes();
        if (bytes[0] == 127 || (bytes[0] == 169 && bytes[1] == 254) || bytes[0] >= 224)
        {
            return false;
        }

        return true;
    }

    private static uint IpToSortable(string ip) =>
        IPAddress.TryParse(ip, out var parsed) && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? BitConverter.ToUInt32(parsed.GetAddressBytes(), 0)
            : uint.MaxValue;
}
