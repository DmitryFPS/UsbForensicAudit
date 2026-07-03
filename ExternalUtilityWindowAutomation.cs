using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Automation;

namespace UsbForensicAudit;

internal sealed class ExternalUtilityRescanResult
{
    public required bool Triggered { get; init; }
    public required string Details { get; init; }
}

internal static class ExternalUtilityWindowAutomation
{
    private const int BmClick = 0x00F5;
    private const int SwRestore = 9;
    private const int VkF5 = 0x74;
    private const int KeyeventfKeyup = 0x0002;

    private static readonly string[] RescanNamePatterns =
    [
        "поиск",
        "скан",
        "scan",
        "search",
        "start",
        "старт",
        "запуск",
        "обнов",
        "refresh",
        "начать",
        "find",
        "detect",
        "провер",
        "анализ",
        "run"
    ];

    public static ExternalUtilityRescanResult TryTriggerRescan(Process utilityProcess, string utilityId)
    {
        var log = new List<string>();

        try
        {
            utilityProcess.Refresh();
            if (utilityProcess.HasExited)
            {
                return Fail("процесс утилиты уже завершён");
            }

            var mainWindow = utilityProcess.MainWindowHandle;
            if (mainWindow == IntPtr.Zero)
            {
                return Fail("окно утилиты не найдено (разверните USBDetector на экране)");
            }

            PrepareWindow(mainWindow);

            if (TryInvokeNamedControl(mainWindow, log))
            {
                return Success(log);
            }

            if (TryClickToolbarButtons(mainWindow, log))
            {
                return Success(log);
            }

            if (utilityId is "usbdetector" or "usbdeview")
            {
                SendFunctionKey(VkF5);
                log.Add("F5");
                Thread.Sleep(250);
                TryClickToolbarButtons(mainWindow, log);
                return new ExternalUtilityRescanResult
                {
                    Triggered = log.Count > 0,
                    Details = string.Join("; ", log)
                };
            }

            return new ExternalUtilityRescanResult
            {
                Triggered = false,
                Details = log.Count == 0
                    ? "не найдена кнопка запуска сканирования"
                    : string.Join("; ", log)
            };
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "External utility rescan automation failed");
            return new ExternalUtilityRescanResult { Triggered = false, Details = ex.Message };
        }
    }

    private static ExternalUtilityRescanResult Fail(string details) =>
        new() { Triggered = false, Details = details };

    private static ExternalUtilityRescanResult Success(List<string> log) =>
        new() { Triggered = true, Details = string.Join("; ", log) };

    private static void PrepareWindow(IntPtr mainWindow)
    {
        if (IsIconic(mainWindow))
        {
            ShowWindow(mainWindow, SwRestore);
        }

        SetForegroundWindow(mainWindow);
        Thread.Sleep(120);
    }

    private static bool TryInvokeNamedControl(IntPtr mainWindow, List<string> log)
    {
        var root = AutomationElement.FromHandle(mainWindow);
        if (root is null)
        {
            return false;
        }

        var candidates = root.FindAll(
            TreeScope.Descendants,
            new OrCondition(
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.MenuItem),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.SplitButton),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Hyperlink)));

        AutomationElement? best = null;
        var bestScore = 0;

        foreach (AutomationElement candidate in candidates)
        {
            if (!candidate.Current.IsEnabled)
            {
                continue;
            }

            var name = ReadElementText(candidate);
            var score = ScoreRescanName(name);
            if (score > bestScore)
            {
                bestScore = score;
                best = candidate;
            }
        }

        if (best is null || bestScore <= 0)
        {
            return false;
        }

        if (best.TryGetCurrentPattern(InvokePattern.Pattern, out var patternObject)
            && patternObject is InvokePattern invokePattern)
        {
            invokePattern.Invoke();
            log.Add($"Invoke:{ReadElementText(best)}");
            Thread.Sleep(250);
            return true;
        }

        return false;
    }

    private static bool TryClickToolbarButtons(IntPtr mainWindow, List<string> log)
    {
        var toolButtons = new List<IntPtr>();
        CollectToolButtons(mainWindow, toolButtons, depth: 0);

        if (toolButtons.Count == 0)
        {
            return false;
        }

        var clicked = 0;
        foreach (var button in toolButtons.Take(4))
        {
            SendMessage(button, BmClick, IntPtr.Zero, IntPtr.Zero);
            log.Add($"BM_CLICK:{GetClassName(button)}");
            clicked++;
            Thread.Sleep(350);
        }

        return clicked > 0;
    }

    private static void CollectToolButtons(IntPtr parent, List<IntPtr> output, int depth)
    {
        EnumChildWindows(
            parent,
            (hWnd, _) =>
            {
                var className = GetClassName(hWnd);
                if (className.Contains("ToolButton", StringComparison.OrdinalIgnoreCase)
                    || (depth <= 2 && className.Equals("Button", StringComparison.OrdinalIgnoreCase)))
                {
                    output.Add(hWnd);
                }

                if (depth < 4)
                {
                    CollectToolButtons(hWnd, output, depth + 1);
                }

                return true;
            },
            IntPtr.Zero);
    }

    private static int ScoreRescanName(string name)
    {
        var score = 0;
        foreach (var pattern in RescanNamePatterns)
        {
            if (name.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                score += pattern.Length;
            }
        }

        return score;
    }

    private static string ReadElementText(AutomationElement element)
    {
        if (element.TryGetCurrentPattern(ValuePattern.Pattern, out var valuePatternObject)
            && valuePatternObject is ValuePattern valuePattern
            && !string.IsNullOrWhiteSpace(valuePattern.Current.Value))
        {
            return valuePattern.Current.Value;
        }

        return element.Current.Name ?? "";
    }

    private static void SendFunctionKey(int virtualKey)
    {
        keybd_event((byte)virtualKey, 0, 0, UIntPtr.Zero);
        keybd_event((byte)virtualKey, 0, KeyeventfKeyup, UIntPtr.Zero);
    }

    private static string GetClassName(IntPtr hWnd)
    {
        var builder = new StringBuilder(256);
        _ = GetClassName(hWnd, builder, builder.Capacity);
        return builder.ToString();
    }

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, int dwFlags, UIntPtr dwExtraInfo);
}
