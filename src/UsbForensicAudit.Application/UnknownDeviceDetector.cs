namespace UsbForensicAudit;

/// <summary>
/// Минимальная идентичность устройства из доказательной базы: ровно те поля,
/// по которым можно узнать устройство при повторном подключении. Загружается
/// одним лёгким запросом без чтения полных сессий.
/// </summary>
public sealed record KnownDeviceIdentity(string Vid, string Pid, string Serial, string DeviceInstanceId);

/// <summary>
/// Детектор неизвестных устройств для резидентного мониторинга: сравнивает
/// текущие live-устройства с базовой линией из всех прошлых сканирований.
/// Чистая логика без WMI и SQLite — тестируется на любой платформе.
/// </summary>
/// <remarks>
/// Правила сопоставления сознательно асимметричны. Если у live-устройства
/// есть аппаратный серийник, оно считается известным только при точном
/// совпадении VID+PID+серийника: другая флешка той же модели — это другое
/// физическое устройство, и о ней нужно предупредить. Если серийника нет
/// (хабы, часть контроллеров), сравнение опускается до VID+PID — иначе
/// каждый порт хаба давал бы ложный алерт.
/// </remarks>
public sealed class UnknownDeviceDetector
{
    private readonly HashSet<string> _strongBaseline;
    private readonly HashSet<string> _weakBaseline;
    private readonly HashSet<string> _pathBaseline;
    private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);

    public UnknownDeviceDetector(IEnumerable<KnownDeviceIdentity> knownDevices)
    {
        _strongBaseline = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _weakBaseline = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _pathBaseline = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var device in knownDevices)
        {
            var vid = Normalize(device.Vid);
            var pid = Normalize(device.Pid);
            var serial = DeviceIdentityGraph.NormalizeSerial(device.Serial);

            if (vid.Length > 0 && pid.Length > 0)
            {
                _weakBaseline.Add($"{vid}:{pid}");
                if (DeviceIdentityGraph.IsHardwareSerial(serial))
                {
                    _strongBaseline.Add($"{vid}:{pid}:{serial}");
                }
            }

            // Серийник известен и без VID/PID: некоторые источники (MountedDevices,
            // WPD) дают только его. Устройство с тем же серийником — то же устройство.
            if (DeviceIdentityGraph.IsHardwareSerial(serial))
            {
                _strongBaseline.Add(serial);
            }

            if (!string.IsNullOrWhiteSpace(device.DeviceInstanceId))
            {
                _pathBaseline.Add(device.DeviceInstanceId.Trim().ToUpperInvariant());
            }
        }
    }

    /// <summary>Сколько идентичностей в базовой линии (для лога при старте).</summary>
    public int BaselineSize => _strongBaseline.Count + _weakBaseline.Count + _pathBaseline.Count;

    /// <summary>
    /// Возвращает устройства из снимка, которых нет в базовой линии и о которых
    /// ещё не предупреждали. Каждое неизвестное устройство возвращается ровно
    /// один раз за время жизни детектора — алерт не повторяется на каждый опрос.
    /// </summary>
    public IReadOnlyList<LiveUsbDevice> DetectNew(IReadOnlyList<LiveUsbDevice> snapshot)
    {
        var unknown = new List<LiveUsbDevice>();
        foreach (var device in snapshot)
        {
            var alertKey = AlertKey(device);
            if (_alerted.Contains(alertKey) || IsKnown(device))
            {
                continue;
            }

            _alerted.Add(alertKey);
            unknown.Add(device);
        }

        return unknown;
    }

    private bool IsKnown(LiveUsbDevice device)
    {
        var vid = Normalize(device.Vid);
        var pid = Normalize(device.Pid);
        var serial = DeviceIdentityGraph.NormalizeSerial(ExtractSerial(device.DeviceId));
        var hasHardwareSerial = DeviceIdentityGraph.IsHardwareSerial(serial);

        if (hasHardwareSerial &&
            (_strongBaseline.Contains(serial) ||
             (vid.Length > 0 && pid.Length > 0 && _strongBaseline.Contains($"{vid}:{pid}:{serial}"))))
        {
            return true;
        }

        if (!hasHardwareSerial && vid.Length > 0 && pid.Length > 0 && _weakBaseline.Contains($"{vid}:{pid}"))
        {
            return true;
        }

        // Последний рубеж — полный путь экземпляра: покрывает устройства без
        // VID/PID и без серийника (съёмные тома, виртуальные узлы DLP-фильтров).
        return _pathBaseline.Contains(device.DeviceId.Trim().ToUpperInvariant());
    }

    private static string AlertKey(LiveUsbDevice device)
    {
        return string.IsNullOrWhiteSpace(device.StableKey)
            ? device.DeviceId.Trim().ToUpperInvariant()
            : device.StableKey.ToUpperInvariant();
    }

    private static string ExtractSerial(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return "";
        }

        var lastSlash = deviceId.LastIndexOf('\\');
        return lastSlash >= 0 ? deviceId[(lastSlash + 1)..] : deviceId;
    }

    private static string Normalize(string value) => value.Trim().ToUpperInvariant();
}
