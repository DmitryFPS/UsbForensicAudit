using Microsoft.Win32;

namespace UsbForensicAudit;

/// <summary>
/// Инфраструктурная реализация <see cref="IOsInfoProvider"/>: читает дату установки
/// Windows из HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion (значение InstallDate).
/// </summary>
public sealed class WindowsOsInfoProvider : IOsInfoProvider
{
    public DateTimeOffset? GetInstalledAtUtc()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key?.GetValue("InstallDate") is int unixSeconds && unixSeconds > 0)
            {
                return DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
            }
        }
        catch
        {
            // InstallDate недоступен — продолжаем без даты установки.
        }

        return null;
    }
}
