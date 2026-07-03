using System.IO;
using System.Management;

namespace UsbForensicAudit;

internal static class EndpointProtectionEnvironment
{
    private static readonly string[] ActiveServiceNames =
    [
        "SnSrvService",
        "SnHwSrv",
        "SnPolicySrv",
        "OmsAgentGate"
    ];

    private static readonly string[] FilterDriverNames =
    [
        "SnDiskFilter",
        "SnFileControl",
        "SnSDD",
        "SnEraser"
    ];

    public static bool IsInstalled { get; } = DetectInstalled();

    public static bool IsProtectionActive { get; } = DetectProtectionActive();

    public static string Summary
    {
        get
        {
            if (!IsInstalled)
            {
                return "";
            }

            return IsProtectionActive
                ? "Активна корпоративная защита USB (DLP) — накопители могут проходить через фильтр дисков."
                : "Корпоративная защита USB установлена, но службы контроля сейчас остановлены.";
        }
    }

    private static bool DetectInstalled()
    {
        if (Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Security Code") is not null)
        {
            return true;
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return Directory.Exists(Path.Combine(programFiles, "Secret Net Studio"))
               || Directory.Exists(Path.Combine(programData, "Security Code", "Secret Net Studio"));
    }

    private static bool DetectProtectionActive()
    {
        if (!IsInstalled)
        {
            return false;
        }

        foreach (var serviceName in ActiveServiceNames)
        {
            if (IsServiceRunning(serviceName))
            {
                return true;
            }
        }

        return IsFilterDriverLoaded();
    }

    private static bool IsServiceRunning(string serviceName)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT State FROM Win32_Service WHERE Name='{serviceName.Replace("'", "''")}'");

            foreach (ManagementObject service in searcher.Get())
            {
                var state = service["State"]?.ToString();
                if (state?.Equals("Running", StringComparison.OrdinalIgnoreCase) == true
                    || state?.Equals("Start Pending", StringComparison.OrdinalIgnoreCase) == true)
                {
                    return true;
                }
            }
        }
        catch
        {
            // Игнорируем ошибки WMI.
        }

        return false;
    }

    private static bool IsFilterDriverLoaded()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT Name, State FROM Win32_SystemDriver WHERE Name='{string.Join("' OR Name='", FilterDriverNames)}'");

            foreach (ManagementObject driver in searcher.Get())
            {
                var state = driver["State"]?.ToString();
                if (state?.Equals("Running", StringComparison.OrdinalIgnoreCase) == true)
                {
                    return true;
                }
            }
        }
        catch
        {
            // Игнорируем ошибки WMI.
        }

        return false;
    }
}
