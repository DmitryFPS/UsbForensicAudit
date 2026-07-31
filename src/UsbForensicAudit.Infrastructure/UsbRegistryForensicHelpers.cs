using System.Globalization;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

internal static class UsbRegistryForensicHelpers
{
    private static readonly Regex ControlSetRegex = new(
        @"^ControlSet\d{3}$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    internal static bool TryParseFileTime(object? value, out DateTimeOffset timestamp)
    {
        timestamp = default;

        if (value is DateTime dateTime)
        {
            return TryValidate(new DateTimeOffset(dateTime.ToUniversalTime()), out timestamp);
        }

        if (value is DateTimeOffset dateTimeOffset)
        {
            return TryValidate(dateTimeOffset.ToUniversalTime(), out timestamp);
        }

        if (value is long signed)
        {
            return TryFromFileTime(signed, out timestamp);
        }

        if (value is ulong unsigned && unsigned <= long.MaxValue)
        {
            return TryFromFileTime((long)unsigned, out timestamp);
        }

        if (value is int integer)
        {
            return TryFromFileTime(integer, out timestamp);
        }

        if (value is byte[] bytes)
        {
            foreach (var offset in CandidateFileTimeOffsets(bytes.Length))
            {
                if (TryFromFileTime(BitConverter.ToInt64(bytes, offset), out timestamp))
                {
                    return true;
                }
            }

            return false;
        }

        if (value is string text)
        {
            text = text.Trim();
            if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric)
                && TryFromFileTime(numeric, out timestamp))
            {
                return true;
            }

            var compactHex = text.Replace("0x", "", StringComparison.OrdinalIgnoreCase)
                .Replace(" ", "", StringComparison.Ordinal)
                .Replace("-", "", StringComparison.Ordinal);
            if (compactHex.Length == 16
                && long.TryParse(compactHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out numeric)
                && TryFromFileTime(numeric, out timestamp))
            {
                return true;
            }

            if (DateTimeOffset.TryParse(
                    text,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var parsed))
            {
                return TryValidate(parsed, out timestamp);
            }
        }

        return false;
    }

    private static IEnumerable<int> CandidateFileTimeOffsets(int length)
    {
        // DEVPROP FILETIME is commonly stored as 8 raw bytes. Some exported/offline
        // representations prepend a 4- or 8-byte type/header.
        if (length >= 8)
        {
            yield return 0;
        }

        if (length >= 12)
        {
            yield return 4;
        }

        if (length >= 16)
        {
            yield return 8;
        }
    }

    private static bool TryFromFileTime(long fileTime, out DateTimeOffset timestamp)
    {
        timestamp = default;
        if (fileTime <= 0)
        {
            return false;
        }

        try
        {
            return TryValidate(DateTimeOffset.FromFileTime(fileTime).ToUniversalTime(), out timestamp);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static bool TryValidate(DateTimeOffset candidate, out DateTimeOffset timestamp)
    {
        timestamp = default;
        var utc = candidate.ToUniversalTime();
        if (utc.Year < 1990 || utc > DateTimeOffset.UtcNow.AddDays(2))
        {
            return false;
        }

        timestamp = utc;
        return true;
    }

    internal static PnpDateSelection SelectPnpDates(
        DateTimeOffset? installDate,
        DateTimeOffset? firstInstallDate,
        DateTimeOffset? lastArrivalDate,
        DateTimeOffset? lastRemovalDate)
    {
        return new PnpDateSelection(
            firstInstallDate ?? installDate,
            lastArrivalDate,
            lastRemovalDate,
            firstInstallDate.HasValue ? "FirstInstallDate (0065)" : installDate.HasValue ? "InstallDate (0064)" : "",
            lastArrivalDate.HasValue ? "LastArrivalDate (0066)" : "",
            lastRemovalDate.HasValue ? "LastRemovalDate (0067)" : "");
    }

    internal static IReadOnlyList<string> BuildControlSetEnumPaths(
        IEnumerable<string> systemSubKeyNames,
        string enumSuffix)
    {
        var names = systemSubKeyNames
            .Where(name => ControlSetRegex.IsMatch(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (names.Length == 0)
        {
            names = ["CurrentControlSet"];
        }

        return names.Select(name => $@"SYSTEM\{name}\Enum\{enumSuffix}").ToArray();
    }

    internal static void MergeRecord(UsbDeviceRecord target, UsbDeviceRecord candidate)
    {
        target.Source = MergeText(target.Source, candidate.Source);
        target.VisualCategory = Prefer(target.VisualCategory, candidate.VisualCategory);
        target.UserMeaning = Prefer(target.UserMeaning, candidate.UserMeaning);
        target.DeviceType = Prefer(target.DeviceType, candidate.DeviceType);
        target.Vid = Prefer(target.Vid, candidate.Vid);
        target.Pid = Prefer(target.Pid, candidate.Pid);
        target.Serial = Prefer(target.Serial, candidate.Serial);
        target.FriendlyName = Prefer(target.FriendlyName, candidate.FriendlyName);
        target.Manufacturer = Prefer(target.Manufacturer, candidate.Manufacturer);
        target.Product = Prefer(target.Product, candidate.Product);
        target.Revision = Prefer(target.Revision, candidate.Revision);
        target.ClassGuid = Prefer(target.ClassGuid, candidate.ClassGuid);
        target.Service = Prefer(target.Service, candidate.Service);
        target.HardwareIds = MergeText(target.HardwareIds, candidate.HardwareIds);
        target.CompatibleIds = MergeText(target.CompatibleIds, candidate.CompatibleIds);
        target.ContainerId = Prefer(target.ContainerId, candidate.ContainerId);
        target.ParentIdPrefix = Prefer(target.ParentIdPrefix, candidate.ParentIdPrefix);
        target.LocationInformation = Prefer(target.LocationInformation, candidate.LocationInformation);
        target.LocationPaths = Prefer(target.LocationPaths, candidate.LocationPaths);
        target.DriveLetters = MergeText(target.DriveLetters, candidate.DriveLetters);
        target.VolumeHints = MergeText(target.VolumeHints, candidate.VolumeHints);
        foreach (var volume in candidate.Volumes)
        {
            if (!target.Volumes.Any(existing =>
                    existing.MappingName.Equals(volume.MappingName, StringComparison.OrdinalIgnoreCase)
                    && existing.Source.Equals(volume.Source, StringComparison.OrdinalIgnoreCase)))
            {
                target.Volumes.Add(volume);
            }
        }

        target.FirstConnectedUtc = PreferFirstConnected(target, candidate);
        target.LastSeenUtc = Max(target.LastSeenUtc, candidate.LastSeenUtc);
        target.LastDisconnectedUtc = Max(target.LastDisconnectedUtc, candidate.LastDisconnectedUtc);
        target.RegistryLastWriteUtc = Max(target.RegistryLastWriteUtc, candidate.RegistryLastWriteUtc);
        target.DateConfidence = MergeText(target.DateConfidence, candidate.DateConfidence);
        target.ConnectionDisplayKind = PreferPreciseKind(target.ConnectionDisplayKind, candidate.ConnectionDisplayKind);
        target.DisconnectDisplayKind = PreferPreciseKind(target.DisconnectDisplayKind, candidate.DisconnectDisplayKind);
        target.IsCurrentlyConnected |= candidate.IsCurrentlyConnected;
    }

    /// <summary>
    /// Имена перечислителей, с которых начинается идентификатор экземпляра устройства.
    /// </summary>
    private static readonly string[] EnumeratorNames =
    [
        "USBSTOR", "USB4", "USBSER", "USB", "SWD", "SCSI", "HID", "PCI",
        "BTHENUM", "BTHLEDEVICE", "BTH", "SDBUS", "SD", "STORAGE", "ACPI"
    ];

    /// <summary>
    /// Перечислители, за которыми стоит физическое устройство: по ним WPD-узел
    /// связывается с записью из Enum.
    /// </summary>
    private static readonly string[] BackingEnumeratorNames =
    [
        "USBSTOR", "USB4", "USB", "SCSI", "SDBUS", "SD"
    ];

    internal static WpdIdentity ParseWpdIdentity(string keyName)
    {
        var decoded = Uri.UnescapeDataString(keyName).Replace('#', '\\').Trim('\\');
        var parts = decoded.Split('\\', StringSplitOptions.RemoveEmptyEntries).ToList();

        // Хвостовой {GUID} — это класс интерфейса устройства (например, GUID_DEVINTERFACE_DISK),
        // одинаковый у всех устройств своего класса. Серийным номером он быть не может.
        if (parts.Count > 1 && IsGuidSegment(parts[^1]))
        {
            parts.RemoveAt(parts.Count - 1);
        }

        // Ведущий _??_ или \??\ — экранированная форма пути устройства, не часть идентификатора.
        if (parts.Count > 0)
        {
            parts[0] = StripDevicePathEscape(parts[0]);
            if (parts[0].Length == 0)
            {
                parts.RemoveAt(0);
            }
        }

        var busIndex = parts.FindIndex(part => IsEnumeratorName(part));
        if (busIndex > 0)
        {
            parts.RemoveRange(0, busIndex);
        }

        var instanceId = string.Join('\\', parts);
        var serial = parts.Count >= 3 ? NormalizeInstanceSuffix(parts[^1]) : "";

        return new WpdIdentity(instanceId, serial, FindBackingInstanceId(parts));
    }

    /// <summary>
    /// Для узла WPD вида SWD\WPDBUSENUM\_??_USBSTOR\... возвращает идентификатор
    /// физического устройства, по которому запись склеивается с данными из Enum.
    /// </summary>
    private static string FindBackingInstanceId(List<string> parts)
    {
        for (var index = 1; index < parts.Count; index++)
        {
            var candidate = StripDevicePathEscape(parts[index]);
            if (candidate.Length > 0 && IsBackingEnumeratorName(candidate) && parts.Count - index >= 3)
            {
                var tail = parts.Skip(index).ToArray();
                tail[0] = candidate;
                return string.Join('\\', tail);
            }
        }

        return "";
    }

    private static bool IsGuidSegment(string segment)
    {
        var trimmed = segment.Trim();
        return trimmed.StartsWith('{')
               && trimmed.EndsWith('}')
               && Guid.TryParse(trimmed, out _);
    }

    private static string StripDevicePathEscape(string segment)
    {
        var value = segment;
        if (value.StartsWith("_??_", StringComparison.Ordinal))
        {
            value = value[4..];
        }
        else if (value.StartsWith("??", StringComparison.Ordinal))
        {
            value = value[2..];
        }

        return value.Trim('\\');
    }

    private static bool IsEnumeratorName(string segment) =>
        EnumeratorNames.Any(name => segment.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static bool IsBackingEnumeratorName(string segment) =>
        BackingEnumeratorNames.Any(name => segment.Equals(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Убирает у идентификатора экземпляра хвост, добавленный шиной (&amp;0, &amp;1 и т.п.),
    /// оставляя серийный номер в том виде, в каком его сообщило устройство.
    /// </summary>
    private static string NormalizeInstanceSuffix(string segment)
    {
        var value = segment.Trim().Trim('{', '}');
        var ampersand = value.LastIndexOf('&');
        if (ampersand > 0 && ampersand < value.Length - 1
            && value[(ampersand + 1)..].All(char.IsDigit))
        {
            value = value[..ampersand];
        }

        return value;
    }

    internal static bool IdentitiesCorrelate(UsbDeviceRecord left, UsbDeviceRecord right)
    {
        if (!string.IsNullOrWhiteSpace(left.DeviceInstanceId)
            && left.DeviceInstanceId.Equals(right.DeviceInstanceId, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(left.ContainerId)
            && left.ContainerId.Equals(right.ContainerId, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!DeviceIdentityGraph.IsHardwareSerial(left.Serial)
            || !DeviceIdentityGraph.IsHardwareSerial(right.Serial))
        {
            return false;
        }

        return DeviceIdentityGraph.NormalizeSerial(left.Serial)
            .Equals(DeviceIdentityGraph.NormalizeSerial(right.Serial), StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeIdentity(string value) =>
        value.Trim().Trim('{', '}').Replace("&0", "", StringComparison.OrdinalIgnoreCase);

    private static string Prefer(string current, string candidate) =>
        string.IsNullOrWhiteSpace(current) ? candidate : current;

    private static string PreferPreciseKind(string current, string candidate)
    {
        static int Score(string value) => value switch
        {
            "PnpDevProperty" => 4,
            "ExactEvent" => 3,
            "RegistryActivity" => 2,
            "LastActivityEstimate" => 1,
            _ => 0
        };

        return Score(candidate) > Score(current) ? candidate : current;
    }

    private static string MergeText(string first, string second)
    {
        return string.Join(
            "; ",
            new[] { first, second }
                .SelectMany(value => value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase));
    }

    private static DateTimeOffset? PreferFirstConnected(UsbDeviceRecord target, UsbDeviceRecord candidate)
    {
        var targetIsFirstInstall = target.DateConfidence.Contains("FirstInstallDate", StringComparison.OrdinalIgnoreCase);
        var candidateIsFirstInstall = candidate.DateConfidence.Contains("FirstInstallDate", StringComparison.OrdinalIgnoreCase);
        if (candidateIsFirstInstall && !targetIsFirstInstall)
        {
            return candidate.FirstConnectedUtc ?? target.FirstConnectedUtc;
        }

        if (targetIsFirstInstall && !candidateIsFirstInstall)
        {
            return target.FirstConnectedUtc ?? candidate.FirstConnectedUtc;
        }

        return Min(target.FirstConnectedUtc, candidate.FirstConnectedUtc);
    }

    private static DateTimeOffset? Min(DateTimeOffset? first, DateTimeOffset? second) =>
        !first.HasValue ? second : !second.HasValue ? first : first.Value < second.Value ? first : second;

    private static DateTimeOffset? Max(DateTimeOffset? first, DateTimeOffset? second) =>
        !first.HasValue ? second : !second.HasValue ? first : first.Value > second.Value ? first : second;
}

internal sealed record PnpDateSelection(
    DateTimeOffset? FirstConnectedUtc,
    DateTimeOffset? LastSeenUtc,
    DateTimeOffset? LastDisconnectedUtc,
    string FirstConnectedProvenance,
    string LastSeenProvenance,
    string LastDisconnectedProvenance);

internal sealed record WpdIdentity(string DeviceInstanceId, string Serial, string BackingDeviceInstanceId = "");
