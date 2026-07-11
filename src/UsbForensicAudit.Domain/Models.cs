using System.Text.Json.Serialization;

namespace UsbForensicAudit;

public sealed class UsbDeviceRecord
{
    public string DeviceInstanceId { get; set; } = "";
    public string Source { get; set; } = "";
    public string VisualCategory { get; set; } = "Unknown";
    public string UserMeaning { get; set; } = "";
    public string DeviceType { get; set; } = "";
    public string Vid { get; set; } = "";
    public string Pid { get; set; } = "";
    public string Serial { get; set; } = "";
    public string FriendlyName { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string Product { get; set; } = "";
    public string Revision { get; set; } = "";
    public string ClassGuid { get; set; } = "";
    public string Service { get; set; } = "";
    public string ContainerId { get; set; } = "";
    public string ParentIdPrefix { get; set; } = "";
    public string LocationInformation { get; set; } = "";
    public string LocationPaths { get; set; } = "";
    public string DriveLetters { get; set; } = "";
    public string VolumeHints { get; set; } = "";
    public DateTimeOffset? FirstConnectedUtc { get; set; }
    public DateTimeOffset? LastSeenUtc { get; set; }
    public DateTimeOffset? LastDisconnectedUtc { get; set; }
    public DateTimeOffset? RegistryLastWriteUtc { get; set; }
    public string DateConfidence { get; set; } = "";
    public bool IsCurrentlyConnected { get; set; }
    public string ConnectionDisplayKind { get; set; } = "";
    public string DisconnectDisplayKind { get; set; } = "";
    public DateTimeOffset CollectedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string RawJson { get; set; } = "";

    [JsonIgnore]
    public string DisplayName => UserDisplayText.DeviceDisplayName(FriendlyName, Manufacturer, Product, DeviceInstanceId);

    [JsonIgnore]
    public string FirstConnectedText => UserDisplayText.ConnectionText(ConnectionDisplayKind, FirstConnectedUtc);

    [JsonIgnore]
    public string LastSeenText => DateDisplay.FormatMoscowOr(LastSeenUtc, UserDisplayText.NoLastSeenEvent);

    [JsonIgnore]
    public string LastDisconnectedText => UserDisplayText.DisconnectText(DisconnectDisplayKind, LastDisconnectedUtc, IsCurrentlyConnected);

    [JsonIgnore]
    public string CategoryText => UserDisplayText.Category(VisualCategory);

    [JsonIgnore]
    public string SourceText => UserDisplayText.Source(Source);

    [JsonIgnore]
    public string DateConfidenceText => UserDisplayText.DateConfidence(DateConfidence);

    [JsonIgnore]
    public string LocationDisplayText => UserDisplayText.Location(LocationInformation, LocationPaths);

    [JsonIgnore]
    public string ManufacturerText => UserDisplayText.ManufacturerName(Manufacturer, FriendlyName, Vid);

    [JsonIgnore]
    public string ModelText => UserDisplayText.ModelName(Product, FriendlyName, Revision, Pid);

    [JsonIgnore]
    public string VidPidText => UserDisplayText.VidPidCodes(Vid, Pid);

    [JsonIgnore]
    public string SerialText => UserDisplayText.Serial(Serial);

    [JsonIgnore]
    public string DeviceTypeText => UserDisplayText.DeviceType(DeviceType);
}

public sealed class EvidenceRecord
{
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Source { get; set; } = "";
    public string Provider { get; set; } = "";
    public string Channel { get; set; } = "";
    public long? RecordId { get; set; }
    public string Computer { get; set; } = "";
    public string SourceFile { get; set; } = "";
    public string SourceRecord { get; set; } = "";
    public string EvidenceCategory { get; set; } = "";
    public string UserExplanation { get; set; } = "";
    public string EventId { get; set; } = "";
    public string Level { get; set; } = "";
    public string DeviceHint { get; set; } = "";
    public string Summary { get; set; } = "";
    public string RawText { get; set; } = "";

    [JsonIgnore]
    public string TimestampText => DateDisplay.FormatMoscow(TimestampUtc);

    [JsonIgnore]
    public string DeviceHintText => ReportText.ForDisplay(DeviceHint, 500);

    [JsonIgnore]
    public string SummaryText => ReportText.ForDisplay(Summary, 800);

    [JsonIgnore]
    public string EvidenceCategoryText => ReportText.ForDisplay(EvidenceCategory, 220);

    [JsonIgnore]
    public string UserExplanationText => ReportText.ForDisplayOrClean(UserExplanation, 800);

    [JsonIgnore]
    public string SourceText => UserDisplayText.Source(Source);
}

public sealed class CleanupFinding
{
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Severity { get; set; } = "Low";
    public string Assessment { get; set; } = "Suspicious";
    public string InitiatorKind { get; set; } = "Unknown";
    public string InitiatorAccount { get; set; } = "";
    public string PossibleTool { get; set; } = "";
    public string Confidence { get; set; } = "Unknown";
    public string Area { get; set; } = "";
    public string Finding { get; set; } = "";
    public string Details { get; set; } = "";
    public string ActionKind { get; set; } = "Unknown";

    [JsonIgnore]
    public string TimestampText => DateDisplay.FormatMoscow(TimestampUtc);

    [JsonIgnore]
    public string SeverityText => UserDisplayText.Severity(Severity);

    [JsonIgnore]
    public string AssessmentText => UserDisplayText.Assessment(Assessment);

    [JsonIgnore]
    public string InitiatorText => UserDisplayText.InitiatorDisplay(InitiatorKind, InitiatorAccount);

    [JsonIgnore]
    public string PossibleToolText => string.IsNullOrWhiteSpace(PossibleTool) ? "не определено" : PossibleTool;

    [JsonIgnore]
    public string ConfidenceText => UserDisplayText.Confidence(Confidence);

    [JsonIgnore]
    public string AreaText => UserDisplayText.Area(Area);

    [JsonIgnore]
    public bool IsSuspicious => Assessment.Equals("Suspicious", StringComparison.OrdinalIgnoreCase);

    [JsonIgnore]
    public string ActionKindText => UserDisplayText.ActionKind(ActionKind);

    [JsonIgnore]
    public bool IsUsbUtilityTool => CleanerToolCatalog.IsUsbForensicUtility(PossibleTool);
}

public sealed class AuditResult
{
    public DateTimeOffset StartedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset FinishedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string ComputerName { get; set; } = Environment.MachineName;
    public string UserName { get; set; } = Environment.UserName;
    public string WindowsVersion { get; set; } = Environment.OSVersion.VersionString;
    public DateTimeOffset? OsInstalledAtUtc { get; set; }
    public bool IsAdministrator { get; set; }

    [JsonIgnore]
    public string OsInstalledAtText => OsInstallInfo.FormatInstallDate(OsInstalledAtUtc);

    [JsonIgnore]
    public string OsInstallGraceNote => OsInstallInfo.GracePeriodExplanation(OsInstalledAtUtc, StartedAtUtc);
    public List<UsbDeviceRecord> Devices { get; } = [];
    public List<EvidenceRecord> Evidence { get; } = [];
    public List<CleanupFinding> CleanupFindings { get; } = [];
    public List<string> SourceWarnings { get; } = [];
}
