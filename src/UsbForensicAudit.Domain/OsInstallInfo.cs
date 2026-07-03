using Microsoft.Win32;

namespace UsbForensicAudit;

public static class OsInstallInfo
{
    public const int PostInstallGraceHours = 3;

    public static TimeSpan PostInstallGracePeriod { get; } = TimeSpan.FromHours(PostInstallGraceHours);

    public static DateTimeOffset? GetInstalledAtUtc()
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

    public static bool IsWithinPostInstallGrace(DateTimeOffset moment, DateTimeOffset installAtUtc)
    {
        return moment >= installAtUtc && moment <= installAtUtc.Add(PostInstallGracePeriod);
    }

    public static bool IsWithinPostInstallGrace(DateTimeOffset moment, DateTimeOffset? installAtUtc)
    {
        return installAtUtc is not null && IsWithinPostInstallGrace(moment, installAtUtc.Value);
    }

    public static string FormatInstallDate(DateTimeOffset? installAtUtc)
    {
        if (installAtUtc is null)
        {
            return "не определена";
        }

        return DateDisplay.FormatMoscow(installAtUtc);
    }

    public static string GracePeriodExplanation(DateTimeOffset? installAtUtc, DateTimeOffset scanAtUtc)
    {
        if (installAtUtc is null)
        {
            return $"Дата установки Windows не определена — окно {PostInstallGraceHours} ч. после установки не применяется.";
        }

        if (IsWithinPostInstallGrace(scanAtUtc, installAtUtc))
        {
            return $"Windows установлена {FormatInstallDate(installAtUtc)}. Первые {PostInstallGraceHours} ч. после установки очистка журналов и setupapi.dev.log остаются в отчёте со статусом «Норма: ОС после установки».";
        }

        return $"Windows установлена {FormatInstallDate(installAtUtc)}. События очистки в первые {PostInstallGraceHours} ч. после этой даты получают статус «Норма: ОС после установки», а не «Подозрительно».";
    }
}
