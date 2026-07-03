namespace UsbForensicAudit;

/// <summary>
/// Инфраструктурная реализация <see cref="IPrivilegeChecker"/> поверх Windows-проверки прав администратора.
/// </summary>
public sealed class WindowsPrivilegeChecker : IPrivilegeChecker
{
    public bool IsAdministrator() => AdminHelper.IsAdministrator();
}
