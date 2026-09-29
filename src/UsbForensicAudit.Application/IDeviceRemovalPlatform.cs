namespace UsbForensicAudit;

public interface IDeviceRemovalPlatform
{
    public string ComputerName { get; }
    public IReadOnlyList<DeviceRemovalNode> ReadInventory();
    public bool IsPresent(string instanceId);
    public bool InstanceExists(string instanceId);
    public void EnsureRemovalSupported();
    public Task<string> BackupAsync(DeviceRemovalPlan plan, CancellationToken cancellationToken);
    public Task<DeviceRemovalCommandResult> RemoveAsync(string instanceId);
    public Task SaveResultAsync(string backupDirectory, DeviceRemovalResult result);
}

public interface IRegistryTracePlatform
{
    // По умолчанию прямое удаление Enum не разрешено: адаптер должен проверить SYSTEM\Select.
    public bool IsActiveEnumPath(string registryPath) => true;
    public string? ReadTraceFingerprint(string registryPath);
    public string GetTraceProtectionReason(DeviceRegistryTrace trace) => DeviceTracePolicy.IsVolumeCachePath(trace.RegistryPath)
        || DeviceTracePolicy.MountedValueName(trace.RegistryPath).Length > 0
        ? "Проверка кэша тома не поддерживается адаптером." : "";
    public Task<DeviceRemovalCommandResult> RemoveTraceAsync(DeviceRegistryTrace trace);
}
