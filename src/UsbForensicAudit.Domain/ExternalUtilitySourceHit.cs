namespace UsbForensicAudit;

public sealed class ExternalUtilitySourceHit
{
    public required string Title { get; init; }
    public required string RegistryPath { get; init; }
    public required bool Found { get; init; }
    public required string ResultText { get; init; }
    public bool LikelyUsbDetectorSource { get; init; }
    public bool IsProcmonEvidence { get; init; }
    public string? Operation { get; init; }
    public DateTimeOffset? ObservedAtUtc { get; init; }
    public int EvidenceRank { get; init; }

    public string DisplayLine
    {
        get
        {
            if (!Found)
            {
                return $"✗ {Title}: {ResultText} ({RegistryPath})";
            }

            if (IsProcmonEvidence)
            {
                var time = ObservedAtUtc is null ? "" : $" [{DateDisplay.FormatMoscow(ObservedAtUtc)}]";
                return $"✓ {Title}: {Operation} → {ResultText}{time} ({RegistryPath})";
            }

            return $"✓ {Title}: {ResultText} ({RegistryPath})";
        }
    }
}
