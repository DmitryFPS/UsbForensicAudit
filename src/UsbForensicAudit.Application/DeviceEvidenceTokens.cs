namespace UsbForensicAudit;

internal static class DeviceEvidenceTokens
{
    public static IReadOnlyList<string> Build(UsbDeviceRecord device)
    {
        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var value in new[]
                 {
                     device.Serial,
                     device.ContainerId,
                     device.ParentIdPrefix,
                     device.DeviceInstanceId
                 })
        {
            var normalized = NormalizeStrong(value);
            if (IsStrong(normalized))
            {
                tokens.Add(normalized);
            }
        }

        foreach (var linkedId in device.LinkedSourceIds)
        {
            var normalized = NormalizeStrong(linkedId);
            if (IsStrong(normalized))
            {
                tokens.Add(normalized);
            }
        }

        // VID/PID and display names identify a model, not a physical instance. They are
        // deliberately excluded so two identical devices cannot inherit each other's dates.
        return tokens.ToArray();
    }

    public static bool Contains(EvidenceRecord evidence, string token)
    {
        return evidence.DeviceHint.Contains(token, StringComparison.OrdinalIgnoreCase)
               || evidence.Summary.Contains(token, StringComparison.OrdinalIgnoreCase)
               || evidence.RawText.Contains(token, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeStrong(string value)
        => value.Trim().Trim('{', '}').Replace(@"\\", @"\");

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
