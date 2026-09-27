namespace UsbForensicAudit;

public sealed record DeviceRemovalNode(
    string InstanceId, string Name, bool? Present,
    string ContainerId = "", string Service = "", string ClassGuid = "",
    string ParentIdPrefix = "", string HardwareIds = "", string AuditInstanceId = "");

public sealed record DeviceRemovalItem(
    string InstanceId, string Name, bool CanRemove, string Reason,
    DeviceRemovalNode? Identity, IReadOnlyList<string> RelatedInstanceIds)
{
    public string RegistryPath => CanRemove ? @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\" + InstanceId : "";
    public string StatusText => CanRemove ? "Можно удалить отключённый экземпляр" : Reason;
}

public sealed record DeviceRemovalPlan(
    string ComputerName, string SessionId, DateTimeOffset CreatedAtUtc,
    IReadOnlyList<DeviceRemovalItem> Items)
{
    public int RemovableCount => Items.Count(x => x.CanRemove);
    public int ProtectedCount => Items.Count - RemovableCount;
}

public sealed record DeviceRemovalCommandResult(int ExitCode, string Output);

public sealed record DeviceRemovalOutcome(string InstanceId, string Name, string Status, string Detail);

public sealed record DeviceRemovalResult(string BackupDirectory, IReadOnlyList<DeviceRemovalOutcome> Items)
{
    public int RemovedCount => Items.Count(x => x.Status == "Removed");
    public int AbsentCount => Items.Count(x => x.Status == "AlreadyAbsent");
    public int FailedCount => Items.Count(x => x.Status is not "Removed" and not "AlreadyAbsent");
    public string Summary => $"Удалено: {RemovedCount}. Уже отсутствуют: {AbsentCount}. Не удалено: {FailedCount}.";
}
