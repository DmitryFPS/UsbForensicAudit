using System.Runtime.InteropServices;

namespace UsbForensicAudit;

internal static class Win32WindowHelper
{
    private const int WmVscroll = 0x0115;
    private const int SbBottom = 7;

    public static int GetWindowTop(IntPtr hWnd)
    {
        GetWindowRect(hWnd, out var rect);
        return rect.Top;
    }

    public static void ScrollToBottom(IntPtr hWnd)
    {
        Win32Message.Send(hWnd, WmVscroll, new IntPtr(SbBottom), IntPtr.Zero);
    }

    public static void PrepareUsbDetectorCapture(IntPtr mainWindow)
    {
        ScrollToBottom(mainWindow);
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
    private static extern bool GetWindowRect(IntPtr hWnd, out Rect lpRect);

}
