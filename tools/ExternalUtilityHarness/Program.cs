using System.Diagnostics;
using System.IO;
using UsbForensicAudit;

namespace UsbForensicAudit.Harness;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        var publishDir = args.Length > 0
            ? args[0]
            : Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "bin", "publish"));

        var targets = new (string Exe, string Id, bool ExpectCapture)[]
        {
            ("USBDeview.exe", "usbdeview", true),
            ("USBDetector.exe", "usbdetector", true),
            ("USBOblivion64.exe", "usboblivion", false)
        };

        var failures = 0;
        foreach (var (exe, _, expectCapture) in targets)
        {
            var path = Path.Combine(publishDir, exe);
            if (!File.Exists(path))
            {
                Console.WriteLine($"SKIP {exe}: not found at {path}");
                continue;
            }

            failures += RunCaptureScenario(path, exe, expectCapture);
        }

        return failures == 0 ? 0 : 1;
    }

    private static int RunCaptureScenario(string exePath, string exeName, bool expectCapture)
    {
        Console.WriteLine();
        Console.WriteLine($"=== {exeName} ===");

        Process? process = null;
        try
        {
            process = Process.Start(new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true
            });

            if (process is null)
            {
                Console.WriteLine("FAIL: could not start process");
                return 1;
            }

            if (!WaitForMainWindow(process, TimeSpan.FromSeconds(20)))
            {
                Console.WriteLine("FAIL: main window not found");
                return 1;
            }

            Thread.Sleep(2500);
            process.Refresh();

            var is32 = ProcessBitnessHelper.Is32BitProcess(process.Id);
            Console.WriteLine($"PID={process.Id}, 32-bit={is32}, title={process.MainWindowTitle}");

            var scanned = RunningExternalUtilityScanner.Scan()
                .FirstOrDefault(x => x.ProcessId == process.Id);

            if (scanned is null)
            {
                Console.WriteLine("FAIL: scanner did not find running utility");
                return 1;
            }

            ExternalUtilityCapture capture;
            try
            {
                capture = ExternalUtilityWindowCaptureService.Capture(scanned);
            }
            catch (Exception ex) when (!expectCapture)
            {
                process.Refresh();
                Console.WriteLine($"EXPECTED: {ex.Message}");
                Console.WriteLine($"Process alive: {!process.HasExited}");
                return process.HasExited ? 1 : 0;
            }
            catch (Exception ex)
            {
                process.Refresh();
                var alive = !process.HasExited;
                Console.WriteLine($"FAIL capture: {ex.Message}");
                Console.WriteLine($"Process alive after failure: {alive}");

                if (exeName.Contains("Oblivion", StringComparison.OrdinalIgnoreCase)
                    && alive
                    && ex.Message.Contains("не найдены таблицы", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("SKIP: USB Oblivion has no list view until cleanup scan is run — use manual paste.");
                    return 0;
                }

                return 1;
            }

            process.Refresh();
            if (process.HasExited)
            {
                Console.WriteLine("FAIL: utility process exited after capture");
                return 1;
            }

            var rowCount = capture.Sections.Sum(x => x.Rows.Count);
            Console.WriteLine($"OK: sections={capture.Sections.Count}, rows={rowCount}");
            foreach (var section in capture.Sections)
            {
                Console.WriteLine($"  - {section.Title}: {section.Rows.Count} rows, headers=[{string.Join(", ", section.ColumnHeaders.Take(4))}...]");
            }

            if (rowCount == 0)
            {
                Console.WriteLine("FAIL: zero rows captured");
                return 1;
            }

            return 0;
        }
        finally
        {
            if (process is not null && !process.HasExited)
            {
                try
                {
                    process.CloseMainWindow();
                    if (!process.WaitForExit(3000))
                    {
                        process.Kill(true);
                    }
                }
                catch
                {
                    // Best effort cleanup.
                }
            }

            process?.Dispose();
        }
    }

    private static bool WaitForMainWindow(Process process, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            process.Refresh();
            if (process.HasExited)
            {
                return false;
            }

            if (process.MainWindowHandle != IntPtr.Zero)
            {
                return true;
            }

            Thread.Sleep(200);
        }

        return false;
    }
}
