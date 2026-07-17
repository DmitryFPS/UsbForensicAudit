using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace UsbForensicAudit;

public sealed class DeviceChangeNotifier : IDisposable
{
    private const int WmDeviceChange = 0x0219;
    private const int DbtDeviceArrival = 0x8000;
    private const int DbtDeviceRemoveComplete = 0x8004;
    private const int DbtDevTypDeviceInterface = 0x00000005;
    private const int DeviceNotifyWindowHandle = 0x00000000;

    private static readonly Guid UsbDeviceInterfaceClass = new("A5DCBF10-6530-11D2-901F-00C04FB951ED");

    private readonly Window _window;
    private HwndSource? _hwndSource;
    private IntPtr _notificationHandle;

    public event EventHandler<string>? DeviceChanged;

    public DeviceChangeNotifier(Window window)
    {
        _window = window;
    }

    public void Start()
    {
        Stop();

        var helper = new WindowInteropHelper(_window);
        if (helper.Handle == IntPtr.Zero)
        {
            helper.EnsureHandle();
        }

        _hwndSource = HwndSource.FromHwnd(helper.Handle);
        _hwndSource?.AddHook(WndProc);

        var filter = new DevBroadcastDeviceInterface
        {
            DbccSize = Marshal.SizeOf<DevBroadcastDeviceInterface>(),
            DbccDeviceType = DbtDevTypDeviceInterface,
            DbccClassGuid = UsbDeviceInterfaceClass
        };

        _notificationHandle = RegisterDeviceNotification(helper.Handle, ref filter, DeviceNotifyWindowHandle);
        if (_notificationHandle == IntPtr.Zero)
        {
            _hwndSource?.RemoveHook(WndProc);
            _hwndSource = null;
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось зарегистрировать уведомления USB.");
        }
    }

    public void Stop()
    {
        if (_notificationHandle != IntPtr.Zero)
        {
            if (!UnregisterDeviceNotification(_notificationHandle))
            {
                AppLog.Error(
                    new Win32Exception(Marshal.GetLastWin32Error()),
                    "Failed to unregister USB notifications");
            }
            _notificationHandle = IntPtr.Zero;
        }

        if (_hwndSource is not null)
        {
            _hwndSource.RemoveHook(WndProc);
            _hwndSource = null;
        }
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg != WmDeviceChange)
        {
            return IntPtr.Zero;
        }

        var eventType = wParam.ToInt32();
        var message = eventType switch
        {
            DbtDeviceArrival => "USB-устройство подключено (системное событие)",
            DbtDeviceRemoveComplete => "USB-устройство отключено (системное событие)",
            _ => ""
        };

        if (!string.IsNullOrWhiteSpace(message))
        {
            DeviceChanged?.Invoke(this, message);
        }

        return IntPtr.Zero;
    }

    public void Dispose()
    {
        Stop();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DevBroadcastDeviceInterface
    {
        public int DbccSize;
        public int DbccDeviceType;
        public int DbccReserved;
        public Guid DbccClassGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 255)]
        public string DbccName;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterDeviceNotification(IntPtr hRecipient, ref DevBroadcastDeviceInterface notificationFilter, int flags);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnregisterDeviceNotification(IntPtr handle);
}
