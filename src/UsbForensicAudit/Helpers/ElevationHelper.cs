using System.ComponentModel;
using System.Diagnostics;
using System.Windows;

namespace UsbForensicAudit;

/// <summary>
/// Перезапуск приложения с правами администратора. Живёт в WPF-проекте:
/// использует MessageBox и Application.Current, которым не место в Infrastructure.
/// Проверка прав (<see cref="AdminHelper.IsAdministrator"/>) остаётся в Infrastructure.
/// </summary>
public static class ElevationHelper
{
    private const int ErrorCancelled = 1223;

    public static bool TryRestartElevated(Window? owner = null)
    {
        if (AdminHelper.IsAdministrator())
        {
            return true;
        }

        var exePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exePath))
        {
            MessageBox.Show(
                owner,
                "Не удалось определить путь к программе для повышения прав.",
                "UsbForensicAudit",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return false;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,
                Verb = "runas"
            });

            Application.Current.Shutdown();
            return false;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            return false;
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Elevation failed");
            MessageBox.Show(
                owner,
                $"Не удалось запустить от администратора: {ex.Message}",
                "UsbForensicAudit",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return false;
        }
    }
}
