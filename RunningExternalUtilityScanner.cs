using System.Diagnostics;

namespace UsbForensicAudit;

public static class RunningExternalUtilityScanner
{
    public static IReadOnlyList<RunningExternalUtility> Scan()
    {
        var results = new List<RunningExternalUtility>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var definition = ExternalUtilityCatalog.MatchProcess(process.ProcessName);
                if (definition is null)
                {
                    continue;
                }

                process.Refresh();
                results.Add(new RunningExternalUtility
                {
                    UtilityId = definition.Id,
                    DisplayName = definition.DisplayName,
                    ProcessId = process.Id,
                    ProcessName = process.ProcessName,
                    MainWindowTitle = process.MainWindowTitle,
                    HasMainWindow = process.MainWindowHandle != IntPtr.Zero
                });
            }
            catch
            {
                // Доступ к некоторым процессам запрещён.
            }
            finally
            {
                process.Dispose();
            }
        }

        return results
            .OrderBy(x => x.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.ProcessId)
            .ToArray();
    }
}
