namespace UsbForensicAudit;

public static class ReportText
{
    public static string ForDisplay(string? value, int maxLength = 4000) =>
        TextSanitizer.NormalizeDisplay(value ?? "", maxLength);

    /// <summary>
    /// Для текста, сгенерированного программой (UserExplanation): не скрывать из-за латиницы в Prefetch/LNK и т.п.
    /// </summary>
    public static string ForDisplayOrClean(string? value, int maxLength = 4000)
    {
        var normalized = ForDisplay(value, maxLength);
        if (!string.IsNullOrWhiteSpace(normalized))
        {
            return normalized;
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        return TextSanitizer.Clean(TextSanitizer.RedactRestrictedTerms(value), maxLength);
    }

    public static string ForPdf(string? value, int maxLength = 4000)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        var normalized = TextSanitizer.NormalizeDisplay(value, maxLength);
        if (!string.IsNullOrWhiteSpace(normalized))
        {
            return normalized;
        }

        return TextSanitizer.Clean(TextSanitizer.RedactRestrictedTerms(value), maxLength);
    }
}
