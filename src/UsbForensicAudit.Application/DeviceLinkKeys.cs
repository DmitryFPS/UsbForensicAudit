namespace UsbForensicAudit;

/// <summary>
/// Признаки, по которым след пользовательской активности можно отнести к
/// конкретному устройству, вместе с надёжностью каждого признака.
///
/// Порядок важен. Серийный номер тома и GUID тома уникальны, поэтому дают
/// надёжную привязку. Буква диска не уникальна: Windows выдаёт первую свободную,
/// и одна и та же буква за год достаётся разным носителям. Если буква
/// встречается больше чем у одного устройства, привязка по ней остаётся
/// предположением и прямо помечена как таковая.
/// </summary>
public sealed class DeviceLinkKeys
{
    private readonly HashSet<string> _volumeSerials = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _volumeGuids = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _driveLetters = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _sharedDriveLetters = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _identityTokens = [];
    private readonly List<string> _portableNames = [];

    public bool HasAnyKey =>
        HasFileActivityKey || _identityTokens.Count > 0;

    /// <summary>
    /// Признаки, по которым можно найти именно работу с файлами. Идентификатора
    /// устройства для этого мало: проводник записывает путь «E:\Фото», а не
    /// идентификатор экземпляра, поэтому без буквы диска, серийного номера тома,
    /// GUID тома или видимого имени искать папки и файлы не по чему.
    /// </summary>
    public bool HasFileActivityKey =>
        _volumeSerials.Count > 0 || _volumeGuids.Count > 0 || _driveLetters.Count > 0
        || _portableNames.Count > 0;

    public IReadOnlyCollection<string> DriveLetters => _driveLetters;

    public static DeviceLinkKeys Build(UsbDeviceRecord device, IReadOnlyCollection<UsbDeviceRecord> allDevices)
    {
        var keys = new DeviceLinkKeys();
        foreach (var volume in device.Volumes)
        {
            AddIfNotEmpty(keys._volumeSerials, NormalizeSerial(volume.VolumeSerialNumber));
            AddIfNotEmpty(keys._volumeGuids, NormalizeGuid(volume.VolumeGuid));
            AddIfNotEmpty(keys._driveLetters, NormalizeDrive(volume.DriveLetter));
        }

        foreach (var letter in device.DriveLetters.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries))
        {
            AddIfNotEmpty(keys._driveLetters, NormalizeDrive(letter));
        }

        keys._identityTokens.AddRange(DeviceEvidenceTokens.Build(device));
        keys._portableNames.AddRange(PortableNames(device));
        foreach (var letter in SharedDriveLetters(device, allDevices, keys._driveLetters))
        {
            keys._sharedDriveLetters.Add(letter);
        }

        return keys;
    }

    /// <summary>
    /// Отвечает, относится ли след к устройству, и по какому признаку. Признаки
    /// проверяются от самого надёжного к самому слабому, чтобы в записи оказалось
    /// лучшее из имеющихся оснований.
    /// </summary>
    public DeviceLinkMatch? Match(EvidenceRecord record)
    {
        var text = $"{record.DeviceHint}\n{record.Summary}\n{record.RawText}";

        foreach (var token in _identityTokens)
        {
            if (DeviceEvidenceTokens.Contains(record, token))
            {
                return new DeviceLinkMatch($"Идентификатор устройства {token}", "High");
            }
        }

        var serial = DeviceActivityBuilder.VolumeSerialRegex().Match(text);
        if (serial.Success && _volumeSerials.Contains(NormalizeSerial(serial.Groups["value"].Value)))
        {
            return new DeviceLinkMatch(
                $"Серийный номер тома {NormalizeSerial(serial.Groups["value"].Value)}", "High");
        }

        foreach (var guid in _volumeGuids)
        {
            if (text.Contains(guid, StringComparison.OrdinalIgnoreCase))
            {
                return new DeviceLinkMatch($"GUID тома {guid}", "High");
            }
        }

        foreach (var name in _portableNames)
        {
            if (text.Contains(name, StringComparison.OrdinalIgnoreCase))
            {
                return new DeviceLinkMatch($"Имя устройства в проводнике «{name}»", "Medium");
            }
        }

        var drive = DeviceActivityBuilder.DriveLetterRegex().Match(text);
        if (!drive.Success)
        {
            return null;
        }

        var letter = NormalizeDrive(drive.Groups["drive"].Value);
        if (!_driveLetters.Contains(letter))
        {
            return null;
        }

        return _sharedDriveLetters.Contains(letter)
            ? new DeviceLinkMatch(
                $"Буква диска {letter}, но эту же букву носили и другие устройства", "Low")
            : new DeviceLinkMatch($"Буква диска {letter}", "Medium");
    }

    public bool IsPathOnDevice(string path)
    {
        var drive = DeviceActivityBuilder.DriveLetterRegex().Match(path);
        return drive.Success && _driveLetters.Contains(NormalizeDrive(drive.Groups["drive"].Value));
    }

    public List<string> Describe()
    {
        var described = new List<string>();
        described.AddRange(_volumeSerials.Select(x => $"серийный номер тома {x}"));
        described.AddRange(_volumeGuids.Select(x => $"GUID тома {x}"));
        described.AddRange(_driveLetters.Select(x => _sharedDriveLetters.Contains(x)
            ? $"буква диска {x} (использовалась несколькими устройствами)"
            : $"буква диска {x}"));
        described.AddRange(_portableNames.Select(x => $"имя в проводнике «{x}»"));
        if (_identityTokens.Count > 0)
        {
            described.Add($"идентификаторы устройства ({_identityTokens.Count})");
        }

        return described;
    }

    /// <summary>
    /// У телефона по MTP нет ни буквы диска, ни серийного номера тома: проводник
    /// сохраняет путь по видимому имени, например «Galaxy A51\Внутренняя память».
    /// Слишком общие имена сюда не берутся — по ним привязка была бы случайной.
    /// </summary>
    private static IEnumerable<string> PortableNames(UsbDeviceRecord device)
    {
        if (device.DeviceKind != DeviceKindResolver.PortableDevice
            && device.DeviceKind != DeviceKindResolver.Camera)
        {
            yield break;
        }

        // Windows обычно записывает одно и то же имя и в FriendlyName, и в Product.
        // Без отсева одно имя перечислялось в отчёте дважды.
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in new[] { device.FriendlyName, device.Product })
        {
            var value = candidate.Trim();
            if (value.Length >= 4 && !IsGenericName(value) && seen.Add(value))
            {
                yield return value;
            }
        }
    }

    private static bool IsGenericName(string value) =>
        value.Equals("USB", StringComparison.OrdinalIgnoreCase)
        || value.Contains("Устройство", StringComparison.OrdinalIgnoreCase)
        || value.Contains("Device", StringComparison.OrdinalIgnoreCase)
        || value.Contains("Volume", StringComparison.OrdinalIgnoreCase)
        || value.Contains("Disk", StringComparison.OrdinalIgnoreCase)
        || value.Contains("Generic", StringComparison.OrdinalIgnoreCase);

    private static IEnumerable<string> SharedDriveLetters(
        UsbDeviceRecord device,
        IReadOnlyCollection<UsbDeviceRecord> allDevices,
        IReadOnlyCollection<string> ownLetters)
    {
        foreach (var letter in ownLetters)
        {
            var owners = allDevices
                .Where(x => !ReferenceEquals(x, device))
                .Where(x => !x.CanonicalDeviceId.Equals(device.CanonicalDeviceId, StringComparison.OrdinalIgnoreCase)
                            || device.CanonicalDeviceId.Length == 0)
                .Count(x => OwnsDriveLetter(x, letter));
            if (owners > 0)
            {
                yield return letter;
            }
        }
    }

    private static bool OwnsDriveLetter(UsbDeviceRecord device, string letter) =>
        device.Volumes.Any(x => NormalizeDrive(x.DriveLetter).Equals(letter, StringComparison.OrdinalIgnoreCase))
        || device.DriveLetters.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries)
            .Any(x => NormalizeDrive(x).Equals(letter, StringComparison.OrdinalIgnoreCase));

    private static void AddIfNotEmpty(HashSet<string> target, string value)
    {
        if (value.Length > 0)
        {
            target.Add(value);
        }
    }

    internal static string NormalizeSerial(string value) =>
        value.Replace("-", "", StringComparison.Ordinal).Trim().ToUpperInvariant();

    internal static string NormalizeGuid(string value)
    {
        var text = value.Trim().Trim('{', '}');
        return Guid.TryParse(text, out var guid) ? guid.ToString("D").ToUpperInvariant() : "";
    }

    internal static string NormalizeDrive(string value)
    {
        var text = value.Trim().TrimEnd('\\', ':');
        return text.Length == 1 && char.IsLetter(text[0]) ? $"{char.ToUpperInvariant(text[0])}:" : "";
    }
}

/// <summary>
/// Основание, по которому след отнесён к устройству, и надёжность этого основания.
/// </summary>
public sealed record DeviceLinkMatch(string Basis, string Confidence);
