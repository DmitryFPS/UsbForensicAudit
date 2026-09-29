using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public static partial class DeviceTracePolicy
{
    private const string VolumeCacheRoot = @"SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\";

    private static bool IsVolumeCacheRelativePath(string path) => path.StartsWith(VolumeCacheRoot, StringComparison.OrdinalIgnoreCase)
        && Regex.IsMatch(path[VolumeCacheRoot.Length..], "^[A-Za-z]:$", RegexOptions.CultureInvariant);

    public static bool IsVolumeCachePath(string path) => NormalizePath(path) is { } normalized
        && IsVolumeCacheRelativePath(normalized[19..]);

    internal static string VolumeCacheDriveLetter(string path) => IsVolumeCachePath(path)
        ? path[^2..].ToUpperInvariant() : "";

    private static DeviceRegistryTrace? BindVolumeCache(string path, UsbDeviceRecord record, string fingerprint)
    {
        // Ключ с буквой диска не идентифицирует USB-устройство. Разрешаем только
        // собственную карточку кэша с её исходными значениями, без расширения группы по метке.
        if (!record.DeviceType.Equals("VolumeLabel", StringComparison.OrdinalIgnoreCase)
            || !path.Equals(NormalizePath(record.DeviceInstanceId), StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(record.RawJson);
            var snapshots = new HashSet<string>(StringComparer.Ordinal);
            ReadVolumeCacheSnapshots(document.RootElement, path, snapshots);
            return snapshots.Count == 1 ? new(path, fingerprint, [], VolumeCacheSnapshotFingerprint: snapshots.Single()) : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static void ReadVolumeCacheSnapshots(JsonElement element, string path, HashSet<string> snapshots)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return;
        }
        if (element.TryGetProperty("RegistryPath", out var sourcePath) && sourcePath.ValueKind == JsonValueKind.String
            && path.Equals(NormalizePath(sourcePath.GetString()!), StringComparison.OrdinalIgnoreCase)
            && element.TryGetProperty("Values", out var values)
            && VolumeCacheValuesFingerprint(values) is { Length: > 0 } snapshot)
        {
            snapshots.Add(snapshot);
        }
        if (element.TryGetProperty("MergedRegistryEvidence", out var merged) && merged.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in merged.EnumerateArray())
            {
                ReadVolumeCacheSnapshots(child, path, snapshots);
            }
        }
    }

    internal static string VolumeCacheValuesFingerprint(JsonElement values)
    {
        if (values.ValueKind != JsonValueKind.Object)
        {
            return "";
        }

        var properties = values.EnumerateObject().ToArray();
        if (properties.Length == 0 || properties.Length > 256
            || properties.Select(x => x.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != properties.Length
            || !properties.Any(x => (x.Name.Equals("VolumeLabel", StringComparison.OrdinalIgnoreCase)
                    || x.Name.Equals("VolumeSerialNumber", StringComparison.OrdinalIgnoreCase))
                && x.Value.ValueKind is JsonValueKind.String or JsonValueKind.Number
                && !string.IsNullOrWhiteSpace(x.Value.ToString())))
        {
            return "";
        }

        // Имена значений реестра не зависят от регистра и порядка перечисления.
        // Значения сохраняются целиком: совпавшего названия тома недостаточно.
        var content = new StringBuilder();
        foreach (var property in properties.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
        {
            content.Append(JsonSerializer.Serialize(property.Name.ToUpperInvariant()));
            content.Append(JsonSerializer.Serialize(property.Value));
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content.ToString())));
    }
}
