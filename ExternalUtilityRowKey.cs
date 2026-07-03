namespace UsbForensicAudit;

public static class ExternalUtilityRowKey
{
    public static string Build(ExternalUtilityRow row) =>
        $"{row.UtilityName}|{row.SectionTitle}|{row.PrimaryText}|{row.CopyText}";
}
