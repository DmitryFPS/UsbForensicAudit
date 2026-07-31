namespace UsbForensicAudit;

/// <summary>
/// Ищет признаки того, что файл с устройства оказался на внутреннем диске.
///
/// Прямого ответа здесь быть не может: Windows не ведёт журнал копирования.
/// Копирование не оставляет собственного следа — остаются только следы того,
/// что файл открывали, и того, что файл с таким именем позже открывали уже с
/// внутреннего диска. Совпадение имён — повод проверить, а не доказательство,
/// и в отчёте оно так и подписано.
/// </summary>
public static class CopyIndicationFinder
{
    public const int MaxIndications = 200;

    /// <summary>
    /// Слишком общие имена вроде «Документ1.docx» совпадают случайно, поэтому
    /// имя должно быть достаточно длинным и иметь расширение.
    /// </summary>
    private const int MinimumFileNameLength = 8;

    private static readonly string[] GenericNames =
    [
        "новый", "документ", "document", "untitled", "без имени", "copy", "копия", "image", "img", "photo",
        "screenshot", "снимок", "temp", "tmp", "download"
    ];

    public static List<CopyIndication> Find(
        IReadOnlyCollection<DeviceActivityEntry> deviceActivity,
        DeviceLinkKeys keys,
        IReadOnlyCollection<EvidenceRecord> evidence)
    {
        var onDevice = new Dictionary<string, DeviceActivityEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in deviceActivity)
        {
            var name = FileName(entry.Path);
            if (name.Length == 0 || onDevice.ContainsKey(name))
            {
                continue;
            }

            onDevice[name] = entry;
        }

        if (onDevice.Count == 0)
        {
            return [];
        }

        var indications = new List<CopyIndication>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in evidence)
        {
            var path = record.DeviceHint.Length > 0 ? record.DeviceHint : record.Summary;
            if (path.Length == 0 || keys.IsPathOnDevice(path) || !IsLocalDiskPath(path))
            {
                continue;
            }

            var name = FileName(path);
            if (name.Length == 0 || !onDevice.TryGetValue(name, out var deviceEntry) || !seen.Add(name))
            {
                continue;
            }

            indications.Add(new CopyIndication
            {
                FileName = name,
                PathOnDevice = deviceEntry.Path,
                LocalPath = path,
                SeenOnDeviceUtc = deviceEntry.TimestampUtc,
                SeenLocallyUtc = record.TimestampUtc,
                Source = record.Source,
                Direction = record.TimestampUtc >= deviceEntry.TimestampUtc
                    ? CopyDirection.ToComputer
                    : CopyDirection.ToDevice,
                Confidence = "Low",
                Basis = "Файл с этим именем открывали и на устройстве, и с внутреннего диска. "
                        + "Журнал изменений NTFS о появлении этого файла на диске ничего не сообщает, "
                        + "поэтому это совпадение имён — повод проверить, а не наблюдаемый перенос."
            });

            if (indications.Count >= MaxIndications)
            {
                break;
            }
        }

        return indications
            .OrderByDescending(x => x.SeenLocallyUtc)
            .ToList();
    }

    /// <summary>
    /// Путь на внутреннем диске — тот, что начинается с буквы диска и не ведёт
    /// на проверяемое устройство. Сетевые пути и пути к телефону по MTP сюда не
    /// относятся: перенос туда — не копирование на эту машину.
    /// </summary>
    internal static bool IsLocalDiskPath(string path)
    {
        var trimmed = path.TrimStart();
        return trimmed.Length >= 3
               && char.IsLetter(trimmed[0])
               && trimmed[1] == ':'
               && (trimmed[2] == '\\' || trimmed[2] == '/');
    }

    internal static string FileName(string path)
    {
        var trimmed = path.Trim().TrimEnd('\\', '/');
        var separator = trimmed.LastIndexOfAny(['\\', '/']);
        var name = separator >= 0 ? trimmed[(separator + 1)..] : trimmed;
        if (name.Length < MinimumFileNameLength || !name.Contains('.'))
        {
            return "";
        }

        var extension = name[(name.LastIndexOf('.') + 1)..];
        if (extension.Length is < 2 or > 5 || !extension.All(char.IsLetterOrDigit))
        {
            return "";
        }

        return GenericNames.Any(x => name.StartsWith(x, StringComparison.OrdinalIgnoreCase))
            ? ""
            : name;
    }
}
