using System.Management;

namespace UsbForensicAudit;

public sealed class WmiUsbMonitor : IDisposable
{
    private static readonly TimeSpan DebounceInterval = TimeSpan.FromMilliseconds(750);
    private static readonly TimeSpan PollingInterval = TimeSpan.FromSeconds(5);
    private readonly object _timerSync = new();
    private ManagementEventWatcher? _watcher;
    private System.Threading.Timer? _debounceTimer;
    private System.Threading.Timer? _pollingTimer;
    private DeviceChangeNotifier? _deviceNotifier;
    private int _refreshPending;
    private int _refreshInProgress;
    private int _isRunning;
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
        Volatile.Write(ref _isRunning, 1);
        StartWatcher();
        RequestRefresh("Старт мониторинга USB");
    }

    public void Stop()
    {
        Volatile.Write(ref _isRunning, 0);
        lock (_timerSync)
        {
            _debounceTimer?.Dispose();
            _debounceTimer = null;
            _pollingTimer?.Dispose();
            _pollingTimer = null;
        }

        if (_watcher is null)
        {
            return;
        }

        try
        {
            _watcher.EventArrived -= OnEventArrived;
            _watcher.Stop();
            _watcher.Dispose();
        }
        catch (Exception exception)
        {
            AppLog.Error(exception, "WMI monitor stop failed");
        }
        finally
        {
            _watcher = null;
        }
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
        catch (Exception exception)
        {
            AppLog.Error(exception, "WMI monitor unavailable; polling fallback enabled");
            if (_watcher is not null)
            {
                try
                {
                    _watcher.EventArrived -= OnEventArrived;
                    _watcher.Dispose();
                }
                catch (Exception cleanupException)
                {
                    AppLog.Error(cleanupException, "Failed to dispose incomplete WMI watcher");
                }
            }
            _watcher = null;
            UsesPollingFallback = true;
            lock (_timerSync)
            {
                _pollingTimer = new System.Threading.Timer(
                    _ => RequestRefresh("Периодическое обновление USB (WMI fallback)"),
                    null,
                    PollingInterval,
                    PollingInterval);
            }
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
        if (Volatile.Read(ref _isRunning) == 0)
        {
            return;
        }

        _lastReason = reason;
        Interlocked.Exchange(ref _refreshPending, 1);

        lock (_timerSync)
        {
            _debounceTimer ??= new System.Threading.Timer(_ => FlushRefresh(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _debounceTimer.Change(DebounceInterval, Timeout.InfiniteTimeSpan);
        }
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
            lock (_timerSync)
            {
                _debounceTimer?.Change(DebounceInterval, Timeout.InfiniteTimeSpan);
            }
            return;
        }

        try
        {
            RefreshRequested?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception exception)
        {
            AppLog.Error(exception, $"USB refresh callback failed: {_lastReason}");
        }
        finally
        {
            Interlocked.Exchange(ref _refreshInProgress, 0);
        }
    }

    public void Dispose()
    {
        Stop();
        if (_deviceNotifier is not null)
        {
            _deviceNotifier.DeviceChanged -= OnExternalDeviceChanged;
            _deviceNotifier = null;
        }
    }
}
