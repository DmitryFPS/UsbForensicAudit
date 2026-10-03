using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public sealed class LiveUsbSnapshotService
{
    private static readonly Regex VidPidRegex = new(@"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _firstSeenByStableKey = new(StringComparer.OrdinalIgnoreCase);

    public string LastWarning { get; private set; } = "";

    public IReadOnlyList<LiveUsbDevice> GetCurrentDevices()
    {
        var snapshot = WindowsPnpSnapshot.Capture();
        LastWarning = snapshot.Error;
        if (!snapshot.Complete) { throw new InvalidOperationException(snapshot.Error); }
        var devicesByStableKey = new Dictionary<string, LiveUsbDevice>(StringComparer.OrdinalIgnoreCase);
        var resolver = UsbVidPidResolver.Build();
        foreach (var record in LivePnpCollector.Collect(snapshot, DateTimeOffset.UtcNow)
                     .Where(x => x.IsCurrentlyConnected && (DeviceTransportClassifier.IsReportable(x) || x.Transport == "Bluetooth")))
        {
            AddOrUpdate(devicesByStableKey, CreateDevice(record.DeviceInstanceId,
                FirstNotEmpty(record.FriendlyName, record.Product, record.DeviceInstanceId),
                record.TransportDisplayText, "Подключено", resolver));
        }
        RemoveMissingDevices(devicesByStableKey.Keys);
        return devicesByStableKey.Values.OrderBy(x => x.DeviceName).ThenBy(x => x.DeviceId).ToArray();
    }
    private LiveUsbDevice CreateDevice(string pnpId, string deviceName, string location, string status, UsbVidPidResolver vidPidResolver)
    {
        var vidPid = ResolveVidPid(pnpId, vidPidResolver);
        if (string.IsNullOrWhiteSpace(vidPid.Vid) || string.IsNullOrWhiteSpace(vidPid.Pid))
        {
            vidPid = CompactVidPidParser.ExtractVidPid(FirstNotEmpty(deviceName, pnpId));
        }

        var stableKey = LiveDeviceIdentity.StableKey(pnpId, vidPid.Vid, vidPid.Pid);
        var firstSeen = _firstSeenByStableKey.GetOrAdd(stableKey, _ => DateTimeOffset.UtcNow);

        var metadata = LiveDeviceMetadataReader.Read(pnpId);
        return new LiveUsbDevice
        {
            ConnectedAtText = DateDisplay.FormatMoscow(firstSeen),
            DeviceName = TextSanitizer.Clean(deviceName, 260),
            DeviceId = pnpId,
            StableKey = stableKey,
            Vid = vidPid.Vid,
            Pid = vidPid.Pid,
            Manufacturer = metadata.Manufacturer,
            Product = metadata.Product,
            HardwareIds = metadata.HardwareIds,
            Revision = metadata.Revision,
            Location = location,
            Status = status
        };
    }

    private static void AddOrUpdate(Dictionary<string, LiveUsbDevice> devicesByStableKey, LiveUsbDevice device)
    {
        if (devicesByStableKey.TryGetValue(device.StableKey, out var existing))
        {
            if (Prefer(device, existing))
            {
                devicesByStableKey[device.StableKey] = device;
            }

            return;
        }

        devicesByStableKey[device.StableKey] = device;
    }

    private static bool Prefer(LiveUsbDevice candidate, LiveUsbDevice current)
    {
        var candidateScore = DeviceScore(candidate);
        var currentScore = DeviceScore(current);
        return candidateScore > currentScore;
    }

    private static int DeviceScore(LiveUsbDevice device)
    {
        var score = 0;
        if (device.DeviceId.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))
        {
            score += 4;
        }

        if (device.DeviceId.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase))
        {
            score += 2;
        }

        if (!string.IsNullOrWhiteSpace(device.Vid) && !string.IsNullOrWhiteSpace(device.Pid))
        {
            score += 2;
        }

        if (device.Status.Equals("OK", StringComparison.OrdinalIgnoreCase))
        {
            score += 1;
        }

        return score;
    }

    private void RemoveMissingDevices(IEnumerable<string> currentStableKeys)
    {
        var current = currentStableKeys.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var knownKey in _firstSeenByStableKey.Keys)
        {
            if (!current.Contains(knownKey))
            {
                _firstSeenByStableKey.TryRemove(knownKey, out _);
            }
        }
    }

    private static string FirstNotEmpty(params string[] values)
    {
        return values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "";
    }

    private static (string Vid, string Pid) ResolveVidPid(string pnpId, UsbVidPidResolver resolver)
    {
        var match = VidPidRegex.Match(pnpId);
        if (match.Success)
        {
            return (match.Groups[1].Value.ToUpperInvariant(), match.Groups[2].Value.ToUpperInvariant());
        }

        return resolver.Resolve(pnpId);
    }

    private sealed class UsbVidPidResolver
    {
        private readonly Dictionary<string, (string Vid, string Pid)> _byStrongKey;

        private UsbVidPidResolver(Dictionary<string, (string Vid, string Pid)> byStrongKey)
        {
            _byStrongKey = byStrongKey;
        }

        public static UsbVidPidResolver Build()
        {
            var map = new Dictionary<string, (string Vid, string Pid)>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var usbRoot = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB");
                if (usbRoot is not null)
                {
                    foreach (var family in usbRoot.GetSubKeyNames())
                    {
                        var vidPid = VidPidRegex.Match(family);
                        if (!vidPid.Success)
                        {
                            continue;
                        }

                        using var familyKey = usbRoot.OpenSubKey(family);
                        if (familyKey is null)
                        {
                            continue;
                        }

                        foreach (var instance in familyKey.GetSubKeyNames())
                        {
                            using var instanceKey = familyKey.OpenSubKey(instance);
                            var value = (vidPid.Groups[1].Value.ToUpperInvariant(), vidPid.Groups[2].Value.ToUpperInvariant());
                            Add(map, instance, value);
                            Add(map, TrimUsbInstance(instance), value);
                            Add(map, instanceKey?.GetValue("ParentIdPrefix")?.ToString(), value);
                            Add(map, instanceKey?.GetValue("ContainerID")?.ToString()?.Trim('{', '}'), value);
                        }
                    }
                }

                using var usbStorRoot = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
                if (usbStorRoot is not null)
                {
                    foreach (var family in usbStorRoot.GetSubKeyNames())
                    {
                        using var familyKey = usbStorRoot.OpenSubKey(family);
                        if (familyKey is null)
                        {
                            continue;
                        }

                        foreach (var instance in familyKey.GetSubKeyNames())
                        {
                            using var instanceKey = familyKey.OpenSubKey(instance);
                            var storageKeys = new[]
                            {
                                instance,
                                TrimUsbInstance(instance),
                                instanceKey?.GetValue("ParentIdPrefix")?.ToString(),
                                instanceKey?.GetValue("ContainerID")?.ToString()?.Trim('{', '}')
                            };

                            var resolved = storageKeys
                                .Where(x => !string.IsNullOrWhiteSpace(x))
                                .Select(x => map.TryGetValue(x!, out var value) ? value : ("", ""))
                                .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x.Item1));

                            if (!string.IsNullOrWhiteSpace(resolved.Item1))
                            {
                                Add(map, $@"USBSTOR\{family}\{instance}", resolved);
                                Add(map, instance, resolved);
                                Add(map, TrimUsbInstance(instance), resolved);
                            }
                        }
                    }
                }
            }
            catch
            {
                // Только по возможности; окно live-режима покажет устройства, даже если корреляция с реестром не удалась.
            }

            return new UsbVidPidResolver(map);
        }

        public (string Vid, string Pid) Resolve(string pnpId)
        {
            foreach (var key in new[] { pnpId, LastSegment(pnpId), TrimUsbInstance(LastSegment(pnpId)) })
            {
                if (!string.IsNullOrWhiteSpace(key) && _byStrongKey.TryGetValue(key, out var value))
                {
                    return value;
                }
            }

            return ("", "");
        }

        private static void Add(Dictionary<string, (string Vid, string Pid)> map, string? key, (string Vid, string Pid) value)
        {
            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value.Vid) || string.IsNullOrWhiteSpace(value.Pid))
            {
                return;
            }

            var normalized = key.Trim().Trim('{', '}');
            // A conflicting historical key must remain unresolved, never last-writer-wins.
            if (map.TryGetValue(normalized, out var previous) && previous != value)
            {
                map[normalized] = ("", "");
                return;
            }
            map[normalized] = value;
        }

        private static string LastSegment(string value)
        {
            var index = value.LastIndexOf('\\');
            return index >= 0 ? value[(index + 1)..] : value;
        }

        private static string TrimUsbInstance(string value)
        {
            var trimmed = value.Trim();
            return trimmed.EndsWith("&0", StringComparison.OrdinalIgnoreCase) ? trimmed[..^2] : trimmed;
        }
    }
}
