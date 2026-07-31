namespace UsbForensicAudit;

/// <summary>
/// Инфраструктурная реализация <see cref="IPrivilegeChecker"/> поверх Windows-проверки прав администратора.
/// </summary>
public sealed class WindowsPrivilegeChecker : IPrivilegeChecker
{
    public bool IsAdministrator() => AdminHelper.IsAdministrator();

    public PrivilegeState AcquireAndDescribe()
    {
        var isSystem = WindowsPrivileges.IsLocalSystem();
        var backup = WindowsPrivileges.TryEnable(WindowsPrivileges.Backup, out var backupError);
        var restore = WindowsPrivileges.TryEnable(WindowsPrivileges.Restore, out _);

        return new PrivilegeState(IsAdministrator(), isSystem, backup, restore)
        {
            BackupPrivilegeError = backupError
        };
    }
}
