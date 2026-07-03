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
    public required string ReportConclusionRow { get; init; }
    public required string ReportConclusionCase { get; init; }
    public required ExternalUtilityIdentifierInfo Identifier { get; init; }
    public required IReadOnlyList<ExternalUtilitySourceHit> SourceHits { get; init; }
    public required string SourceChecksText { get; init; }
    public required string FullExplanation { get; init; }
    public string? ReportConclusionProcmon { get; init; }
    public string? ProcmonSessionDirectory { get; init; }

    public bool HasProcmonEvidence =>
        SourceHits.Any(x => x.IsProcmonEvidence && x.Found);

    /// <summary>Формулировка по строке (для отчёта по одной записи утилиты).</summary>
    public string ReportConclusion => ReportConclusionRow;

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
