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
    /// <summary>
    /// Сериализует доступ к буферу обмена между чтениями. SemaphoreSlim вместо lock,
    /// чтобы владение можно было передать зависшему рабочему потоку (см. TryRead).
    /// </summary>
    private static readonly SemaphoreSlim ClipboardGate = new(1, 1);

    /// <summary>Максимальное ожидание, если предыдущее чтение ещё не завершилось.</summary>
    private static readonly TimeSpan GateTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Максимальная длительность одного чтения: клик + Ctrl+A/Ctrl+C обычно занимают
    /// доли секунды; всё, что дольше, означает зависшее целевое окно (модальный диалог, UAC).
    /// </summary>
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(8);

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
        if (!ClipboardGate.Wait(GateTimeout))
        {
            // Предыдущее чтение зависло и всё ещё владеет буфером обмена —
            // не выстраиваем очередь, вызывающий код обойдётся снапшотом без clipboard.
            return null;
        }

        // 0 — владеет вызывающий поток; 1 — вызывающий отдал владение (таймаут);
        // 2 — рабочий поток завершился. Кто видит «чужую» отметку — освобождает семафор.
        var ownership = 0;
        Win32ListViewReader.ListViewSnapshot? result = null;

        var worker = new Thread(() =>
        {
            try
            {
                result = TryReadCore(mainWindowHandle, listViewHandle, options);
            }
            catch
            {
                // Результат остаётся null: ошибки чтения чужого окна не критичны.
            }
            finally
            {
                if (Interlocked.Exchange(ref ownership, 2) == 1)
                {
                    ClipboardGate.Release();
                }
            }
        })
        {
            IsBackground = true,
            Name = "UsbForensicAudit clipboard reader"
        };

        try
        {
            worker.SetApartmentState(ApartmentState.STA);
            worker.Start();
        }
        catch
        {
            ClipboardGate.Release();
            return null;
        }

        if (worker.Join(ReadTimeout))
        {
            ClipboardGate.Release();
            return result;
        }

        // Целевое окно зависло: возвращаемся без результата, а владение семафором
        // передаём рабочему потоку — он освободит его, если когда-нибудь «отвиснет».
        // До этого момента clipboard-путь честно отключён (Wait выше вернёт false).
        if (Interlocked.Exchange(ref ownership, 1) == 2)
        {
            ClipboardGate.Release();
        }

        return null;
    }

    private static Win32ListViewReader.ListViewSnapshot? TryReadCore(
        IntPtr mainWindowHandle,
        IntPtr listViewHandle,
        ClipboardReadOptions? options)
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
            // Буфер обмена может быть заблокирован другим приложением.
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
                // Восстановление по возможности (без гарантий).
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
                    // Игнорируем ошибки восстановления фокуса.
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
        Win32Message.Send(listViewHandle, WmLbuttondown, (IntPtr)1, lParam);
        Win32Message.Send(listViewHandle, WmLbuttonup, IntPtr.Zero, lParam);
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

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, int dwFlags, UIntPtr dwExtraInfo);
}
