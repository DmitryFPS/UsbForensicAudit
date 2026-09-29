namespace UsbForensicAudit;

public sealed record DeviceRemovalNode(
    string InstanceId, string Name, bool? Present,
    string ContainerId = "", string Service = "", string ClassGuid = "",
    string ParentIdPrefix = "", string HardwareIds = "", string AuditInstanceId = "", string ParentDeviceInstanceId = "");

public sealed record DeviceRemovalItem(
    string InstanceId, string Name, bool CanRemove, string Reason,
    DeviceRemovalNode? Identity, IReadOnlyList<string> RelatedInstanceIds, DeviceRegistryTrace? Trace = null)
{
    public string RegistryPath => Trace?.RegistryPath ?? (CanRemove ? @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\" + InstanceId : "");
    public string StatusText => !CanRemove ? Reason : Trace is null ? "Удаление экземпляра Windows"
        : Trace.Fingerprint.Length == 0 ? "Уже отсутствует в Windows — проверка перед очисткой базы"
        : Trace.MountedValueSnapshot.Length > 0 ? "Удаление значения сопоставления тома" : "Удаление записи реестра";
}

public sealed record DeviceRegistryTrace(string RegistryPath, string Fingerprint,
    IReadOnlyList<string> DeviceIds, string Vid = "", string Pid = "", string VolumeCacheSnapshotFingerprint = "",
    string MountedValueSnapshot = "", string UsbAncestorInstanceId = "");

public sealed record DatabaseDeviceRemovalResult(int RemovedCount, string BackupDirectory);

public sealed record DeviceRemovalDatabaseRecord(string DeviceInstanceId, IReadOnlyList<string> TargetIds);

public sealed record DeviceRemovalPlan(
    string ComputerName, string SessionId, DateTimeOffset CreatedAtUtc,
    IReadOnlyList<DeviceRemovalItem> Items)
{
    public IReadOnlyList<DeviceRemovalDatabaseRecord> DatabaseRecords { get; init; } = [];
    public int RemovableCount => Items.Count(x => x.CanRemove);
    public int ProtectedCount => Items.Count - RemovableCount;
}

public sealed record DeviceRemovalCommandResult(int ExitCode, string Output);

public sealed record DeviceRemovalOutcome(string InstanceId, string Name, string Status, string Detail);

public sealed record DeviceRemovalResult(string BackupDirectory, IReadOnlyList<DeviceRemovalOutcome> Items)
{
    public DatabaseDeviceRemovalResult? DatabaseRemoval { get; init; }
    public string DatabaseError { get; init; } = "";
    public string ProtocolError { get; init; } = "";
    public int SkippedCount { get; init; }
    public int RemovedCount => Items.Count(x => x.Status == "Removed");
    public int AbsentCount => Items.Count(x => x.Status == "AlreadyAbsent");
    public int FailedCount => Items.Count(x => x.Status is not "Removed" and not "AlreadyAbsent");
    public string Summary => $"Удалено из Windows: {RemovedCount}. Уже отсутствуют: {AbsentCount}. Не удалено: {FailedCount}."
        + $" Пропущено при проверке: {SkippedCount}."
        + (FailedCount > 0 || SkippedCount > 0 ? " Очистка выполнена не полностью." : "")
        + (DatabaseRemoval is null ? "" : $" Удалено карточек из базы: {DatabaseRemoval.RemovedCount}.")
        + (DatabaseError.Length == 0 ? "" : $" Не удалось обновить базу: {DatabaseError}")
        + (ProtocolError.Length == 0 ? "" : $" Не удалось сохранить протокол: {ProtocolError}");
}
