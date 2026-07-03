using System.Diagnostics;
using System.Runtime.InteropServices;

namespace UsbForensicAudit;

internal static class ProcessBitnessHelper
{
    /// <summary>
    /// SendMessage с указателями на структуры небезопасен при разной разрядности (64-битный читатель → 32-битный ListView аварийно завершает целевой процесс).
    /// </summary>
    public static bool RequiresUiAutomationForWindowMessages(int processId)
    {
        if (!Environment.Is64BitProcess)
        {
            return false;
        }

        return Is32BitProcess(processId);
    }

    public static bool Is32BitProcess(int processId)
    {
        if (!Environment.Is64BitOperatingSystem)
        {
            return true;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            if (!IsWow64Process(process.Handle, out var isWow64))
            {
                return false;
            }

            return isWow64;
        }
        catch
        {
            return false;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);
}
