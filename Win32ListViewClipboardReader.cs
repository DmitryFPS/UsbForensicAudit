using System.Runtime.InteropServices;
using System.Windows;

namespace UsbForensicAudit;

internal sealed class ClipboardReadOptions
{
    public bool BringTargetToForeground { get; init; }
    public bool RestorePreviousForeground { get; init; } = true;
}

internal static class Win32ListViewClipboardReader
{
    private const int SwRestore = 9;
    private const int VkControl = 0x11;
    private const int VkA = 0x41;
    private const int VkC = 0x43;
    private const int KeyeventfKeyup = 0x0002;

    public static Win32ListViewReader.ListViewSnapshot? TryRead(
        IntPtr mainWindowHandle,
        IntPtr listViewHandle,
        ClipboardReadOptions? options = null)
    {
        options ??= new ClipboardReadOptions { BringTargetToForeground = true };
        GetWindowRect(listViewHandle, out var rect);
        string? backupText = null;
        var hadText = false;
        var previousForeground = GetForegroundWindow();

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
            if (options.BringTargetToForeground)
            {
                if (IsIconic(mainWindowHandle))
                {
                    ShowWindow(mainWindowHandle, SwRestore);
                }

                SetForegroundWindow(mainWindowHandle);
            }

            ActivateListView(listViewHandle);
            Thread.Sleep(options.BringTargetToForeground ? 60 : 30);

            SendCtrlKey(VkA);
            Thread.Sleep(40);
            SendCtrlKey(VkC);
            Thread.Sleep(90);

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

            if (options.RestorePreviousForeground
                && previousForeground != IntPtr.Zero
                && previousForeground != mainWindowHandle)
            {
                try
                {
                    SetForegroundWindow(previousForeground);
                }
                catch
                {
                    // Ignore focus restore failures.
                }
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
        GetClientRect(listViewHandle, out var rect);
        var x = Math.Max(8, (rect.Right - rect.Left) / 2);
        var y = Math.Max(8, (rect.Bottom - rect.Top) / 2);

        var point = new Point { X = x, Y = y };
        ClientToScreen(listViewHandle, ref point);
        SetCursorPos(point.X, point.Y);
        Thread.Sleep(20);

        var lParam = (IntPtr)((y << 16) | (x & 0xFFFF));
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
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr SetFocus(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hWnd, out Rect lpRect);

    [DllImport("user32.dll")]
    private static extern bool GetClientRect(IntPtr hWnd, out Rect lpRect);

    [DllImport("user32.dll")]
    private static extern bool ClientToScreen(IntPtr hWnd, ref Point lpPoint);

    [DllImport("user32.dll")]
    private static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, int dwFlags, UIntPtr dwExtraInfo);
}
