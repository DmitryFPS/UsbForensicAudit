namespace UsbForensicAudit;

internal static class DeviceEvidenceTokens
{
    public static IReadOnlyList<string> Build(UsbDeviceRecord device)
    {
        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        Add(tokens, device.Serial, guidAllowed: false);
        Add(tokens, device.ParentIdPrefix, guidAllowed: false);
        Add(tokens, device.DeviceInstanceId, guidAllowed: false);
        Add(tokens, device.ContainerId, guidAllowed: true);

        foreach (var linkedId in device.LinkedSourceIds)
        {
            Add(tokens, linkedId, guidAllowed: false);
        }

        foreach (var alias in device.IdentityAliases)
        {
            Add(tokens, alias, guidAllowed: false);
        }

        // VID/PID and display names identify a model, not a physical instance. They are
        // deliberately excluded so two identical devices cannot inherit each other's dates.
        return tokens.ToArray();
    }

    private static void Add(HashSet<string> tokens, string value, bool guidAllowed)
    {
        // Класс интерфейса устройства и заглушка контейнера общие для всех устройств
        // своего класса: по ним нельзя привязывать события к экземпляру.
        if (WellKnownDeviceGuids.IsNonIdentifying(value))
        {
            return;
        }

        if (!guidAllowed && WellKnownDeviceGuids.IsBareGuid(value))
        {
            return;
        }

        var normalized = NormalizeStrong(value);
        if (IsStrong(normalized))
        {
            tokens.Add(normalized);
        }
    }

    public static bool Contains(EvidenceRecord evidence, string token)
    {
        return evidence.DeviceHint.Contains(token, StringComparison.OrdinalIgnoreCase)
               || evidence.Summary.Contains(token, StringComparison.OrdinalIgnoreCase)
               || evidence.RawText.Contains(token, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeStrong(string value)
        => DevicePathNormalizer.NormalizeDeviceId(value);

    private static bool IsStrong(string value)
    {
        if (value.Length < 8
            || value.Equals("00000000", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Windows", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Volume", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Generic", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return value.Contains('\\')
               || value.Contains('&')
               || value.Contains('-')
               || value.Any(char.IsDigit);
    }
}
