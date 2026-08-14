using System.IO;
using System.Management;

namespace UsbForensicAudit;

internal static class EndpointProtectionEnvironment
{
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(10);

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

    private static readonly Lazy<Task<bool>> Probe = new(StartProbe);

    public static bool IsInstalled { get; } = DetectInstalled();

    /// <summary>
    /// Активны ли службы контроля USB. Значение приходит из фонового опроса WMI:
    /// обращаться к нему следует там, где короткая пауза допустима (сканирование,
    /// отчёты, старт мониторинга), но не на пути запуска приложения.
    /// </summary>
    public static bool IsProtectionActive => ReadProbeResult();

    /// <summary>
    /// Запускает опрос, не дожидаясь результата. Вызывается при старте, чтобы
    /// к моменту первого сканирования значение уже было готово.
    /// </summary>
    public static void BeginProbe()
    {
        if (IsInstalled)
        {
            _ = Probe.Value;
        }
    }

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

    /// <summary>
    /// Опрос вынесен в фоновую задачу: даже на исправной машине первое обращение к WMI
    /// из свежего процесса занимает секунды, а на машине с повреждённым репозиторием
    /// запрос не возвращается вовсе. Раньше он выполнялся в UI-потоке до показа окна,
    /// и приложение зависало без единого окна.
    /// </summary>
    private static Task<bool> StartProbe()
    {
        return Task.Run(() =>
        {
            var started = DateTime.UtcNow;
            var active = ProbeProtection();
            var elapsed = (DateTime.UtcNow - started).TotalMilliseconds;

            EndpointProtectionState.IsProtectionActive = active;
            AppLog.Info($"Опрос служб корпоративной защиты занял {elapsed:F0} мс, активна={active}.");
            return active;
        });
    }

    private static bool ReadProbeResult()
    {
        if (!IsInstalled)
        {
            return false;
        }

        var probe = Probe.Value;
        if (probe.Wait(ProbeTimeout))
        {
            return probe.Result;
        }

        AppLog.Info(
            $"WMI не ответил за {ProbeTimeout.TotalSeconds:F0} с при опросе служб корпоративной защиты. " +
            "Защита считается неактивной.");
        return false;
    }

    private static bool ProbeProtection()
    {
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
