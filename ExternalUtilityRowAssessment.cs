namespace UsbForensicAudit;

public enum ExternalUtilityVerdictLevel
{
    Confirmed,
    Probable,
    Indirect,
    Virtual,
    DateArtifact,
    NotFound,
    Unknown
}

public sealed class ExternalUtilityRowAssessment
{
    public required ExternalUtilityVerdictLevel Level { get; init; }
    public required string VerdictTitle { get; init; }
    public required string ProbableOrigin { get; init; }
    public required string UsbDetectorNote { get; init; }
    public required string AuditMatchSummary { get; init; }
    public required string ReportConclusion { get; init; }
    public required ExternalUtilityIdentifierInfo Identifier { get; init; }
    public required string FullExplanation { get; init; }

    public string VerdictTitleWithEmoji => Level switch
    {
        ExternalUtilityVerdictLevel.Confirmed => "✓ " + VerdictTitle,
        ExternalUtilityVerdictLevel.Probable => "≈ " + VerdictTitle,
        ExternalUtilityVerdictLevel.Indirect => "○ " + VerdictTitle,
        ExternalUtilityVerdictLevel.Virtual => "VM " + VerdictTitle,
        ExternalUtilityVerdictLevel.DateArtifact => "⚠ " + VerdictTitle,
        ExternalUtilityVerdictLevel.NotFound => "? " + VerdictTitle,
        _ => VerdictTitle
    };
}
