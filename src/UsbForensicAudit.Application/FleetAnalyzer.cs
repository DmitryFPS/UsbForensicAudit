namespace UsbForensicAudit;

/// <summary>
/// Сопоставляет устройства между сканами разных машин и находит носители,
/// перемещавшиеся между ПК. Работает поверх набора готовых результатов аудита
/// (по одному на машину), поэтому чистый и тестируемый без хранилища.
/// </summary>
public static class FleetAnalyzer
{
    public static FleetSummary Analyze(IEnumerable<AuditResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);

        var machines = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var byIdentity = new Dictionary<string, Accumulator>(StringComparer.OrdinalIgnoreCase);

        foreach (var result in results)
        {
            var machine = string.IsNullOrWhiteSpace(result.ComputerName) ? result.SessionId : result.ComputerName;
            machines.Add(machine);

            foreach (var device in result.Devices)
            {
                var key = IdentityKey(device, machine);
                if (key is null)
                {
                    continue;
                }

                if (!byIdentity.TryGetValue(key, out var acc))
                {
                    acc = new Accumulator { DisplayName = device.DisplayName };
                    byIdentity[key] = acc;
                }

                acc.Machines.Add(machine);
                acc.Observe(device.FirstConnectedUtc);
                acc.Observe(device.LastSeenUtc);
            }
        }

        var devices = byIdentity
            .Select(pair => new FleetDevice
            {
                IdentityKey = pair.Key,
                DisplayName = pair.Value.DisplayName,
                Machines = pair.Value.Machines.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
                FirstSeenUtc = pair.Value.FirstSeenUtc,
                LastSeenUtc = pair.Value.LastSeenUtc,
                IdentifiedBySerial = pair.Key.StartsWith("SN:", StringComparison.Ordinal)
            })
            // Сначала перемещавшиеся между машинами и по большему числу машин —
            // с них начинают разбор.
            .OrderByDescending(x => x.IsCrossMachine)
            .ThenByDescending(x => x.MachineCount)
            .ThenBy(x => x.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new FleetSummary { Devices = devices, MachineCount = machines.Count };
    }

    /// <summary>
    /// Ключ идентичности носителя: серийный номер, если он есть и осмысленный;
    /// иначе — VID:PID. Устройства без серийника и без VID/PID (хабы, части шины)
    /// в кросс-машинный анализ не берём: их «совпадение» ничего не значит.
    /// </summary>
    private static string? IdentityKey(UsbDeviceRecord device, string machine)
    {
        var vid = device.Vid.Trim().ToUpperInvariant();
        var pid = device.Pid.Trim().ToUpperInvariant();
        var hasModel = IsUsbCode(vid) && IsUsbCode(pid);
        if (DeviceIdentityGraph.IsHardwareSerial(device.Serial))
        {
            var serial = DeviceIdentityGraph.NormalizeSerial(device.Serial);
            // Без модели совпадение серийника не переносим между компьютерами.
            return hasModel ? $"SN:{vid}:{pid}:{serial}" : $"LOCAL:{machine.ToUpperInvariant()}:{serial}";
        }

        if (hasModel)
        {
            return $"VIDPID:{vid}:{pid}";
        }

        return null;
    }

    private static bool IsUsbCode(string value) => value.Length == 4 && value.All(Uri.IsHexDigit);

    private sealed class Accumulator
    {
        public string DisplayName = "";
        public HashSet<string> Machines { get; } = new(StringComparer.OrdinalIgnoreCase);
        public DateTimeOffset? FirstSeenUtc { get; private set; }
        public DateTimeOffset? LastSeenUtc { get; private set; }

        public void Observe(DateTimeOffset? moment)
        {
            if (moment is null)
            {
                return;
            }

            if (FirstSeenUtc is null || moment < FirstSeenUtc)
            {
                FirstSeenUtc = moment;
            }

            if (LastSeenUtc is null || moment > LastSeenUtc)
            {
                LastSeenUtc = moment;
            }
        }
    }
}
