using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace UsbForensicAudit;

public static class DarkWindowChrome
{
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaUseImmersiveDarkModeOld = 19;

    private const uint SwpNomove = 0x0002;
    private const uint SwpNosize = 0x0001;
    private const uint SwpNozorder = 0x0004;
    private const uint SwpNoactivate = 0x0010;
    private const uint SwpFramechanged = 0x0020;

    public static void Apply(Window window, bool hideUntilReady = false)
    {
        if (window.GetValue(AttachedProperty) as bool? == true)
        {
            Refresh(window);
            return;
        }

        window.SetValue(AttachedProperty, true);

        if (hideUntilReady)
        {
            window.Visibility = Visibility.Hidden;
        }

        window.SourceInitialized += (_, _) =>
        {
            Refresh(window);
            if (hideUntilReady)
            {
                window.Visibility = Visibility.Visible;
            }
        };

        window.StateChanged += (_, _) => Refresh(window);
        window.Activated += (_, _) => Refresh(window);

        var helper = new WindowInteropHelper(window);
        if (helper.Handle == IntPtr.Zero)
        {
            helper.EnsureHandle();
        }

        Refresh(window);
    }

    private static void Refresh(Window window)
    {
        var handle = new WindowInteropHelper(window).Handle;
        if (handle == IntPtr.Zero)
        {
            return;
        }

        var enabled = 1;
        if (DwmSetWindowAttribute(handle, DwmwaUseImmersiveDarkMode, ref enabled, sizeof(int)) != 0)
        {
            DwmSetWindowAttribute(handle, DwmwaUseImmersiveDarkModeOld, ref enabled, sizeof(int));
        }

        SetWindowTheme(handle, "DarkMode_Explorer", null);
        DwmFlush();

        SetWindowPos(
            handle,
            IntPtr.Zero,
            0,
            0,
            0,
            0,
            SwpNomove | SwpNosize | SwpNozorder | SwpNoactivate | SwpFramechanged);
    }

    private static readonly DependencyProperty AttachedProperty =
        DependencyProperty.RegisterAttached(
            "DarkChromeAttached",
            typeof(bool),
            typeof(DarkWindowChrome),
            new PropertyMetadata(false));

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    [DllImport("dwmapi.dll")]
    private static extern void DwmFlush();

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    private static extern int SetWindowTheme(IntPtr hWnd, string? pszSubAppName, string? pszSubIdList);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowPos(
        IntPtr hWnd,
        IntPtr hWndInsertAfter,
        int x,
        int y,
        int cx,
        int cy,
        uint uFlags);
}
