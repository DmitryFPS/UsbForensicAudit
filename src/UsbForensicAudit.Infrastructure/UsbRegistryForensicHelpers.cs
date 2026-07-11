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

    internal static WpdIdentity ParseWpdIdentity(string keyName)
    {
        var decoded = Uri.UnescapeDataString(keyName).Replace('#', '\\').Trim('\\');
        var instanceId = decoded;

        var usbStart = decoded.IndexOf(@"USB\", StringComparison.OrdinalIgnoreCase);
        if (usbStart >= 0)
        {
            instanceId = decoded[usbStart..];
        }
        else
        {
            var swdStart = decoded.IndexOf(@"SWD\WPDBUSENUM\", StringComparison.OrdinalIgnoreCase);
            if (swdStart >= 0)
            {
                instanceId = decoded[swdStart..];
            }
        }

        var parts = instanceId.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        var serial = parts.Length >= 3 ? parts[^1].Trim('{', '}') : "";
        if (serial.EndsWith("&0", StringComparison.OrdinalIgnoreCase))
        {
            serial = serial[..^2];
        }

        return new WpdIdentity(instanceId, serial);
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

internal sealed record WpdIdentity(string DeviceInstanceId, string Serial);
