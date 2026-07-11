namespace UsbForensicAudit;

internal static class DeviceEvidenceTokens
{
    public static IReadOnlyList<string> Build(UsbDeviceRecord device)
    {
        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(device.Vid) && !string.IsNullOrWhiteSpace(device.Pid))
        {
            tokens.Add($"VID_{device.Vid}");
            tokens.Add($"PID_{device.Pid}");
            tokens.Add($"VID_{device.Vid}&PID_{device.Pid}");
            tokens.Add($"Vid_{device.Vid}Pid_{device.Pid}");
            tokens.Add($"{device.Vid}:{device.Pid}");
        }

        foreach (var field in new[]
                 {
                     device.FriendlyName,
                     device.Product,
                     device.Manufacturer,
                     device.Serial,
                     device.DeviceInstanceId
                 })
        {
            foreach (var token in CompactVidPidParser.BuildMatchTokens(field))
            {
                tokens.Add(token);
            }
        }

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
