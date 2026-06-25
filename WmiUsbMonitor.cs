using System.Management;

namespace UsbForensicAudit;

public sealed class WmiUsbMonitor : IDisposable
{
    private static readonly TimeSpan DebounceInterval = TimeSpan.FromMilliseconds(750);
    private ManagementEventWatcher? _watcher;
    private System.Threading.Timer? _debounceTimer;
    private DeviceChangeNotifier? _deviceNotifier;
    private int _refreshPending;
    private int _refreshInProgress;
    private string _lastReason = "Обновление списка USB";

    public event EventHandler<string>? DeviceChanged;
    public event EventHandler? RefreshRequested;

    public bool UsesPollingFallback { get; private set; }

    public void AttachDeviceNotifier(DeviceChangeNotifier notifier)
    {
        if (_deviceNotifier == notifier)
        {
            return;
        }

        if (_deviceNotifier is not null)
        {
            _deviceNotifier.DeviceChanged -= OnExternalDeviceChanged;
        }

        _deviceNotifier = notifier;
        _deviceNotifier.DeviceChanged += OnExternalDeviceChanged;
    }

    public void Start()
    {
        Stop();
        StartWatcher();
        RequestRefresh("Старт мониторинга USB");
    }

    public void Stop()
    {
        _debounceTimer?.Dispose();
        _debounceTimer = null;

        if (_deviceNotifier is not null)
        {
            _deviceNotifier.DeviceChanged -= OnExternalDeviceChanged;
            _deviceNotifier = null;
        }

        if (_watcher is null)
        {
            return;
        }

        _watcher.EventArrived -= OnEventArrived;
        _watcher.Stop();
        _watcher.Dispose();
        _watcher = null;
    }

    private void StartWatcher()
    {
        UsesPollingFallback = false;

        try
        {
            var query = new WqlEventQuery("SELECT * FROM Win32_DeviceChangeEvent WHERE EventType = 2 OR EventType = 3");
            _watcher = new ManagementEventWatcher(query);
            _watcher.EventArrived += OnEventArrived;
            _watcher.Start();
        }
        catch
        {
            _watcher = null;
            UsesPollingFallback = true;
        }
    }

    private void OnExternalDeviceChanged(object? sender, string message)
    {
        DeviceChanged?.Invoke(this, message);
        RequestRefresh(message);
    }

    private void OnEventArrived(object sender, EventArrivedEventArgs e)
    {
        var eventType = e.NewEvent.Properties["EventType"]?.Value?.ToString();
        var message = eventType switch
        {
            "2" => "USB/PnP устройство подключено",
            "3" => "USB/PnP устройство отключено",
            _ => $"PnP изменение: {eventType}"
        };

        DeviceChanged?.Invoke(this, message);
        RequestRefresh(message);
    }

    private void RequestRefresh(string reason)
    {
        _lastReason = reason;
        Interlocked.Exchange(ref _refreshPending, 1);

        _debounceTimer ??= new System.Threading.Timer(_ => FlushRefresh(), null, DebounceInterval, Timeout.InfiniteTimeSpan);
        _debounceTimer.Change(DebounceInterval, Timeout.InfiniteTimeSpan);
    }

    private void FlushRefresh()
    {
        if (Interlocked.Exchange(ref _refreshPending, 0) == 0)
        {
            return;
        }

        if (Interlocked.Exchange(ref _refreshInProgress, 1) == 1)
        {
            Interlocked.Exchange(ref _refreshPending, 1);
            _debounceTimer?.Change(DebounceInterval, Timeout.InfiniteTimeSpan);
            return;
        }

        try
        {
            RefreshRequested?.Invoke(this, EventArgs.Empty);
        }
        finally
        {
            Interlocked.Exchange(ref _refreshInProgress, 0);
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
