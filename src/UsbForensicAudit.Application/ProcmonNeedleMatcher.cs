namespace UsbForensicAudit;

internal static class ProcmonNeedleMatcher
{
    public static IReadOnlyList<string> BuildNeedles(ExternalUtilityRow row, ExternalUtilityIdentifierInfo identifier)
    {
        var needles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (identifier.HasVid)
        {
            needles.Add(identifier.Vid!);
            needles.Add($"VID_{identifier.Vid}");
            needles.Add($"vid_{identifier.Vid}");
        }

        if (identifier.HasFullPair)
        {
            needles.Add(identifier.Pid!);
            needles.Add($"PID_{identifier.Pid}");
            needles.Add($"VID_{identifier.Vid}&PID_{identifier.Pid}");
            needles.Add($"VID_{identifier.Vid}&PID_{identifier.Pid}".Replace("&", "#"));
        }

        if (!string.IsNullOrWhiteSpace(identifier.VendorLookup.VendorName))
        {
            needles.Add(identifier.VendorLookup.VendorName);
        }

        if (!string.IsNullOrWhiteSpace(identifier.VendorLookup.ProductName))
        {
            needles.Add(identifier.VendorLookup.ProductName);
        }

        if (!string.IsNullOrWhiteSpace(row.PrimaryText) && row.PrimaryText.Length >= 3)
        {
            needles.Add(row.PrimaryText.Trim());
        }

        foreach (var value in row.Values.Values)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length < 4)
            {
                continue;
            }

            if (ExternalUtilityIdentifierParser.TryParseHexId(value, out var hex))
            {
                needles.Add(hex);
                needles.Add($"VID_{hex}");
            }

            if (value.Contains("VID_", StringComparison.OrdinalIgnoreCase)
                || value.Contains("USB\\", StringComparison.OrdinalIgnoreCase)
                || value.Contains("Mount", StringComparison.OrdinalIgnoreCase))
            {
                needles.Add(value);
            }
        }

        return needles
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .OrderByDescending(x => x.Length)
            .ToArray();
    }

    public static bool MatchesPathOrDetail(string path, string? detail, IReadOnlyList<string> needles)
    {
        var haystack = $"{path} {detail}";
        return needles.Any(needle => haystack.Contains(needle, StringComparison.OrdinalIgnoreCase));
    }
}
