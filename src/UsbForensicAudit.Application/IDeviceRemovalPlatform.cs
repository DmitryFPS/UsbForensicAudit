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
    public string? ReadTraceFingerprint(string registryPath);
    public Task<DeviceRemovalCommandResult> RemoveTraceAsync(DeviceRegistryTrace trace);
}
