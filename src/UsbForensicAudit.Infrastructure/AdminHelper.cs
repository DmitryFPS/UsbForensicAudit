using System.Security.Principal;

namespace UsbForensicAudit;

/// <summary>
/// Проверка прав администратора. UI-часть повышения прав (перезапуск с UAC,
/// MessageBox) перенесена в WPF-проект — см. ElevationHelper.
/// </summary>
public static class AdminHelper
{
    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
