using System.Text.Json.Serialization;

namespace UsbForensicAudit;

public sealed class UsbDeviceRecord
{
    public string SessionId { get; set; } = "";
    public string DeviceInstanceId { get; set; } = "";
    public string CanonicalDeviceId { get; set; } = "";
    public string PhysicalDeviceGroup { get; set; } = "";
    public bool IsCanonicalPrimary { get; set; }
    public string IdentityConfidence { get; set; } = "";
    public List<string> LinkedSourceIds { get; set; } = [];
    public List<string> IdentityProvenance { get; set; } = [];

    /// <summary>
    /// Дополнительные идентификаторы, под которыми это же физическое устройство
    /// встречается в других источниках. Для узла WPD здесь лежит идентификатор
    /// экземпляра USBSTOR, стоящего за ним.
    /// </summary>
    public List<string> IdentityAliases { get; set; } = [];
    public List<VolumeIdentity> Volumes { get; set; } = [];
    public string Source { get; set; } = "";
    public string VisualCategory { get; set; } = "Unknown";
    public string UserMeaning { get; set; } = "";
    public string DeviceType { get; set; } = "";

    /// <summary>
    /// Что за устройство: носитель, телефон, устройство ввода. Хранится отдельно
    /// от способа подключения, потому что это разные вопросы.
    /// </summary>
    public string DeviceKind { get; set; } = "Unknown";
    public string Transport { get; set; } = "Unknown";
    public string TransportConfidence { get; set; } = "Unknown";
    public List<string> TransportProvenance { get; set; } = [];
    public string Connection { get; set; } = "Unknown";
    public string ConnectionConfidence { get; set; } = "Unknown";
    public List<string> ConnectionProvenance { get; set; } = [];
    public string Classification { get; set; } = "Unknown";
    public string ClassificationConfidence { get; set; } = "Unknown";
    public List<string> ClassificationProvenance { get; set; } = [];
    public string Vid { get; set; } = "";
    public string Pid { get; set; } = "";
    public string Serial { get; set; } = "";
    public string FriendlyName { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string Product { get; set; } = "";
    public string Revision { get; set; } = "";
    public string ClassGuid { get; set; } = "";
    public string Service { get; set; } = "";
    public string HardwareIds { get; set; } = "";
    public string CompatibleIds { get; set; } = "";
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

    /// <summary>
    /// Откуда взята каждая дата. Пустое значение при заполненной дате означает
    /// ошибку конвейера: дата без происхождения в отчёт попадать не должна.
    /// </summary>
    public string FirstConnectedProvenance { get; set; } = "";

    public string LastSeenProvenance { get; set; } = "";
    public string LastDisconnectedProvenance { get; set; } = "";

    /// <summary>
    /// Отдельные сеансы работы устройства. Первая и последняя дата не показывают,
    /// сколько раз устройство подключали и как долго оно оставалось в машине.
    /// </summary>
    public List<ConnectionSession> Sessions { get; set; } = [];

    /// <summary>
    /// Замечания о том, насколько можно верить идентификаторам устройства:
    /// серийный номер и VID/PID устройство сообщает о себе само.
    /// </summary>
    public List<IdentityTrustFinding> IdentityTrustFindings { get; set; } = [];

    /// <summary>
    /// Признаки переноса файлов между этим устройством и внутренним диском.
    /// Ищутся при сканировании, пока журнал изменений NTFS ещё под рукой: сам
    /// журнал в результат не сохраняется, а найденные совпадения — сохраняются.
    /// </summary>
    public List<CopyIndication> CopyIndications { get; set; } = [];

    /// <summary>
    /// Запись досталась от эталонного образа: устройство видел сборщик образа,
    /// а не человек, работающий за этой машиной.
    /// </summary>
    public bool InheritedFromReferenceImage { get; set; }
    /// <summary>
    /// Имя, взятое у другой записи того же устройства. Windows называет
    /// родительскую запись по классу — «USB Composite Device», — а модель
    /// пишет у функции: «Integrated Camera». В списке устройство стоит одной
    /// строкой, и в ней должно быть имя вещи, а не имя класса. Собственные
    /// значения записи при этом не меняются: FriendlyName, Mfg и DeviceDesc
    /// остаются такими, какими их хранит реестр.
    /// </summary>
    public string GroupDisplayName { get; set; } = "";

    public bool IsCurrentlyConnected { get; set; }
    public string ConnectionDisplayKind { get; set; } = "";
    public string DisconnectDisplayKind { get; set; } = "";
    public DateTimeOffset CollectedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string RawJson { get; set; } = "";

    [JsonIgnore]
    public string DisplayName => string.IsNullOrWhiteSpace(GroupDisplayName)
        ? OwnDisplayName
        : GroupDisplayName;

    /// <summary>Имя из значений самой записи, без заимствования у соседей.</summary>
    [JsonIgnore]
    public string OwnDisplayName =>
        UserDisplayText.DeviceDisplayName(FriendlyName, Manufacturer, Product, DeviceInstanceId);

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

    [JsonIgnore]
    public string DeviceKindText => DeviceKindResolver.Describe(DeviceKind);

    /// <summary>
    /// Приносили ли устройство с собой. Отдельно от того, что это за устройство
    /// и как оно подключалось: во вкладке по этому признаку красится строка.
    /// </summary>
    [JsonIgnore]
    public string Externality => DeviceExternality.Resolve(this);

    [JsonIgnore]
    public string ExternalityText => DeviceExternality.Describe(Externality);

    [JsonIgnore]
    public bool IsExternalDevice => DeviceExternality.IsExternal(Externality);

    [JsonIgnore]
    public string IdentityTrustText => IdentityTrustFindings.Count == 0
        ? "Идентификаторы выглядят достоверно."
        : string.Join(" ", IdentityTrustFindings.Select(x => $"{x.Title}: {x.Explanation}"));

    /// <summary>
    /// Есть ли основание не доверять отождествлению устройства по серийному номеру.
    /// </summary>
    [JsonIgnore]
    public bool IdentityIsUntrustworthy =>
        IdentityTrustFindings.Any(x => x.Severity.Equals("High", StringComparison.OrdinalIgnoreCase));

    [JsonIgnore]
    public string TransportDisplayText => DeviceKindResolver.DescribeTransport(Transport, Connection);

    [JsonIgnore]
    public string OriginDisplayText => DeviceKindResolver.DescribeOrigin(Classification);

    [JsonIgnore]
    public string ClassificationDisplayText =>
        $"{DeviceKindText}. {TransportDisplayText}. {OriginDisplayText} "
        + $"({DeviceKindResolver.DescribeConfidence(ClassificationConfidence)})";

    /// <summary>
    /// Технические значения для тех, кто сверяет отчёт с реестром.
    /// </summary>
    [JsonIgnore]
    public string ClassificationCodesText =>
        $"kind={DeviceKind}; transport={Transport}; connection={Connection}; class={Classification}";

    [JsonIgnore]
    public string ClassificationEvidenceText => string.Join("; ",
        TransportProvenance.Concat(ConnectionProvenance).Concat(ClassificationProvenance)
            .Distinct(StringComparer.OrdinalIgnoreCase));
}

public sealed class VolumeIdentity
{
    public string MappingName { get; set; } = "";
    public string VolumeGuid { get; set; } = "";
    public string VolumeSerialNumber { get; set; } = "";
    public string DiskSignature { get; set; } = "";
    public string DiskId { get; set; } = "";
    public long? PartitionOffset { get; set; }
    public string DriveLetter { get; set; } = "";
    public string DevicePath { get; set; } = "";
    public string Source { get; set; } = "";
    public string Confidence { get; set; } = "";
    public List<string> Provenance { get; set; } = [];
}

public sealed class EvidenceRecord
{
    public string SessionId { get; set; } = "";
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset AcquisitionTimestampUtc { get; set; } = DateTimeOffset.UtcNow;
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
    public string SourceSha256 { get; set; } = "";
    public string Provenance { get; set; } = "";
    public string EvidenceStrength { get; set; } = "Indirect";
    public string Confidence { get; set; } = "Low";
    public string UserSid { get; set; } = "";
    public string ResolvedUserName { get; set; } = "";
    public DateTimeOffset? RegistryLastWriteUtc { get; set; }
    public bool CanEstablishConnectionDate { get; set; }

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
    public string SessionId { get; set; } = "";
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
    public string Provenance { get; set; } = "";

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

    /// <summary>
    /// Запуск утилиты для работы с USB и наличие средства удаления следов — не
    /// доказательство очистки, поэтому подозрительными такие находки называть
    /// нельзя. Но и молчать о них в сводке нельзя: раньше отчёт писал «явных
    /// подозрительных признаков не обнаружено» в тот же день, когда
    /// пользователь запускал USBDeview, а на диске лежал USB Oblivion.
    /// </summary>
    [JsonIgnore]
    public bool NeedsAttention =>
        !IsSuspicious
        && ActionKind is "ToolLaunch" or "ToolPresence"
        && (IsUsbUtilityTool || CleanerToolCatalog.IsTraceRemovalTool(PossibleTool));

    [JsonIgnore]
    public string ActionKindText => UserDisplayText.ActionKind(ActionKind);

    [JsonIgnore]
    public bool IsUsbUtilityTool => CleanerToolCatalog.IsUsbForensicUtility(PossibleTool);
}

public sealed class AuditResult
{
    public string SessionId { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset StartedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset FinishedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string ComputerName { get; set; } = Environment.MachineName;
    public string UserName { get; set; } = Environment.UserName;
    public string WindowsVersion { get; set; } = Environment.OSVersion.VersionString;
    public DateTimeOffset? OsInstalledAtUtc { get; set; }
    public bool IsAdministrator { get; set; }

    /// <summary>
    /// Права, с которыми выполнялось сканирование. По ним видно, можно ли считать
    /// отсутствие устройства в отчёте доказательством.
    /// </summary>
    public PrivilegeState Privileges { get; set; } = new(false, false, false, false);

    /// <summary>
    /// Следы развёртывания из готового образа. Нужны, чтобы не приписывать
    /// человеку устройства, попавшие в реестр при подготовке образа.
    /// </summary>
    public ReferenceImageTrace ReferenceImage { get; set; } = new();

    [JsonIgnore]
    public string OsInstalledAtText => OsInstallInfo.FormatInstallDate(OsInstalledAtUtc);

    [JsonIgnore]
    public string OsInstallGraceNote => OsInstallInfo.GracePeriodExplanation(OsInstalledAtUtc, StartedAtUtc);
    // Public setters are intentional: AuditStorage deserializes complete sessions through
    // System.Text.Json, which otherwise cannot restore get-only collection properties.
    public List<UsbDeviceRecord> Devices { get; set; } = [];
    public List<EvidenceRecord> Evidence { get; set; } = [];
    public List<CleanupFinding> CleanupFindings { get; set; } = [];
    public List<string> SourceWarnings { get; set; } = [];
    public ScanCoverageReport Coverage { get; set; } = new();

    /// <summary>
    /// Связи с внешним миром помимо USB: сети Wi-Fi, провод, туннели VPN, пары по
    /// Bluetooth, серверы с сетевыми папками, узлы удалённого стола, посещённые
    /// сайты. Вынесены в отдельный список, а не в доказательства, потому что у
    /// каждой связи своя история сеансов и свои обращения — их нужно показывать
    /// вместе со связью, а не отдельными строками журнала.
    /// </summary>
    public List<NetworkConnectionRecord> NetworkConnections { get; set; } = [];

    /// <summary>
    /// Обстановка вокруг машины: сети Wi-Fi в эфире и устройства в той же
    /// сети. Снимается отдельной кнопкой, поэтому у обычного сканирования
    /// остаётся пустой.
    /// </summary>
    public NetworkEnvironmentSnapshot NetworkEnvironment { get; set; } = new();

    /// <summary>
    /// За какой период прочитан журнал изменений NTFS на каждом внутреннем томе.
    /// Сами записи журнала в результат не сохраняются: их десятки тысяч, и после
    /// поиска признаков переноса они не нужны. А вот глубина журнала нужна: без
    /// неё «признаков переноса нет» читается шире, чем позволяют данные.
    /// </summary>
    public List<FileChangeJournalState> FileChangeJournals { get; set; } = [];
}

public sealed class ScanCoverageReport
{
    public List<SourceCoverage> Sources { get; set; } = [];
    public int CanonicalDeviceCount { get; set; }
    public int CanonicalDevicesWithExactDates { get; set; }

    public double ExactDateCoveragePercent => CanonicalDeviceCount == 0
        ? 0
        : Math.Round(100d * CanonicalDevicesWithExactDates / CanonicalDeviceCount, 2);
}

public sealed class SourceCoverage
{
    public string Source { get; set; } = "";
    public string Status { get; set; } = "NotRun";
    public int Count { get; set; }
    public bool Capped { get; set; }
    public string Error { get; set; } = "";
    public int Limit { get; set; }
}
