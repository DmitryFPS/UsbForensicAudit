using System.ComponentModel;
using System.Runtime.InteropServices;

namespace UsbForensicAudit;

internal static class Win32Message
{
    private const uint SmtoAbortIfHung = 0x0002;
    private const uint SmtoErrorOnExit = 0x0020;
    private const uint DefaultTimeoutMilliseconds = 2_000;

    public static IntPtr Send(
        IntPtr window,
        int message,
        IntPtr wParam,
        IntPtr lParam,
        uint timeoutMilliseconds = DefaultTimeoutMilliseconds)
    {
        if (window == IntPtr.Zero)
        {
            return IntPtr.Zero;
        }

        Marshal.SetLastPInvokeError(0);
        var delivered = SendMessageTimeout(
            window,
            message,
            wParam,
            lParam,
            SmtoAbortIfHung | SmtoErrorOnExit,
            timeoutMilliseconds,
            out var result);

        if (delivered != IntPtr.Zero)
        {
            return result;
        }

        var error = Marshal.GetLastPInvokeError();
        throw error == 0
            ? new TimeoutException($"Окно 0x{window.ToInt64():X} не ответило за {timeoutMilliseconds} мс.")
            : new Win32Exception(error, $"Не удалось отправить сообщение окну 0x{window.ToInt64():X}.");
    }

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(
        IntPtr hWnd,
        int msg,
        IntPtr wParam,
        IntPtr lParam,
        uint flags,
        uint timeout,
        out IntPtr result);
}
