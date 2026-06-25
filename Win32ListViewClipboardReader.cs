using System.Runtime.InteropServices;
using System.Text;
using System.Windows;

namespace UsbForensicAudit;

internal static class Win32ListViewClipboardReader
{
    private const int SwRestore = 9;
    private const int VkControl = 0x11;
    private const int VkA = 0x41;
    private const int VkC = 0x43;
    private const int KeyeventfKeyup = 0x0002;

    public static Win32ListViewReader.ListViewSnapshot? TryRead(IntPtr mainWindowHandle, IntPtr listViewHandle)
    {
        GetWindowRect(listViewHandle, out var rect);
        string? backupText = null;
        var hadText = false;

        try
        {
            if (Clipboard.ContainsText())
            {
                backupText = Clipboard.GetText();
                hadText = true;
            }
        }
        catch
        {
            // Clipboard may be locked by another app.
        }

        try
        {
            ShowWindow(mainWindowHandle, SwRestore);
            SetForegroundWindow(mainWindowHandle);
            ActivateListView(listViewHandle);
            Thread.Sleep(120);

            SendCtrlKey(VkA);
            Thread.Sleep(80);
            SendCtrlKey(VkC);
            Thread.Sleep(180);

            if (!Clipboard.ContainsText())
            {
                return null;
            }

            return ParseClipboardText(listViewHandle, rect, Clipboard.GetText());
        }
        catch
        {
            return null;
        }
        finally
        {
            try
            {
                if (hadText && backupText is not null)
                {
                    Clipboard.SetText(backupText);
                }
                else
                {
                    Clipboard.Clear();
                }
            }
            catch
            {
                // Best effort restore.
            }
        }
    }

    private static Win32ListViewReader.ListViewSnapshot ParseClipboardText(
        IntPtr listViewHandle,
        Rect rect,
        string clipboardText)
    {
        var lines = clipboardText
            .Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToArray();

        if (lines.Length == 0)
        {
            return new Win32ListViewReader.ListViewSnapshot(listViewHandle, rect.Top, rect.Left, [], []);
        }

        var parsed = lines.Select(ParseLine).ToArray();
        var columnCount = parsed.Max(x => x.Count);
        var headers = Enumerable.Range(0, columnCount).Select(i => $"Колонка {i + 1}").ToArray();

        if (LooksLikeHeaderRow(parsed[0]))
        {
            headers = parsed[0]
                .Select(x => ExternalUtilityColumnNormalizer.NormalizeHeaderName(TextSanitizer.NormalizeDisplay(x, 200)))
                .ToArray();
            parsed = parsed.Skip(1).ToArray();
        }

        var rows = parsed
            .Where(cells => cells.Any(x => !string.IsNullOrWhiteSpace(x)))
            .Select<IReadOnlyList<string>, IReadOnlyList<string>>(cells => cells)
            .ToArray();

        return new Win32ListViewReader.ListViewSnapshot(listViewHandle, rect.Top, rect.Left, headers, rows);
    }

    private static List<string> ParseLine(string line)
    {
        if (line.Contains('\t'))
        {
            return line.Split('\t').Select(x => TextSanitizer.NormalizeDisplay(x, 500)).ToList();
        }

        if (line.Contains("  ", StringComparison.Ordinal))
        {
            return line.Split(["  "], StringSplitOptions.None)
                .Select(x => TextSanitizer.NormalizeDisplay(x.Trim(), 500))
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToList();
        }

        return [TextSanitizer.NormalizeDisplay(line, 500)];
    }

    private static bool LooksLikeHeaderRow(IReadOnlyList<string> cells)
    {
        var joined = string.Join(' ', cells).ToUpperInvariant();
        return joined.Contains("VID") || joined.Contains("PID") || joined.Contains("UID")
               || joined.Contains("DEVICE") || joined.Contains("УСТРОЙ");
    }

    private static void ActivateListView(IntPtr listViewHandle)
    {
        var point = new Point { X = 12, Y = 12 };
        ClientToScreen(listViewHandle, ref point);
        SetCursorPos(point.X, point.Y);
        Thread.Sleep(40);

        var lParam = (IntPtr)((12 << 16) | 12);
        SendMessage(listViewHandle, WmLbuttondown, (IntPtr)1, lParam);
        SendMessage(listViewHandle, WmLbuttonup, IntPtr.Zero, lParam);
        SetFocus(listViewHandle);
    }

    private const int WmLbuttondown = 0x0201;
    private const int WmLbuttonup = 0x0202;

    private static void SendCtrlKey(int key)
    {
        keybd_event((byte)VkControl, 0, 0, UIntPtr.Zero);
        keybd_event((byte)key, 0, 0, UIntPtr.Zero);
        keybd_event((byte)key, 0, KeyeventfKeyup, UIntPtr.Zero);
        keybd_event((byte)VkControl, 0, KeyeventfKeyup, UIntPtr.Zero);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Point
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr SetFocus(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hWnd, out Rect lpRect);

    [DllImport("user32.dll")]
    private static extern bool ClientToScreen(IntPtr hWnd, ref Point lpPoint);

    [DllImport("user32.dll")]
    private static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, int dwFlags, UIntPtr dwExtraInfo);
}
