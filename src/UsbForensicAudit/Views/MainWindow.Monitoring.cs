using System.Windows;

namespace UsbForensicAudit;

/// <summary>
/// Live-мониторинг USB: подписка на события Windows, окно текущих устройств,
/// автоснимок после изменения состава USB. Отдельный файл — мониторинг живёт
/// по своим событиям и не пересекается с ручными операциями пользователя.
/// </summary>
public partial class MainWindow
{
    private UnknownDeviceDetector? _unknownDeviceDetector;
    private UnknownDeviceAlertWindow? _unknownDeviceAlertWindow;

    /// <summary>Счётчик алертов за календарный день — для строки состояния.</summary>
    private int _alertsToday;
    private DateOnly _alertsDay = DateOnly.FromDateTime(DateTime.Now);

    private void MonitorButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _deviceChangeNotifier.Start();
            _monitor.Start();
            _ = InitializeUnknownDeviceDetectorAsync();
            ShowAndRefreshActiveDevicesWindow();
            _vm.IsMonitoringActive = true;
            MonitorButton.IsEnabled = false;
            StopMonitorButton.IsEnabled = true;
            ShowActiveDevicesButton.IsEnabled = true;
            AppendLog("Live-мониторинг запущен. Обновление идёт по событиям Windows, без постоянного опроса каждые 2 секунды.");
            UpdateMonitorStatusBar(active: true);
            if (_monitor.UsesPollingFallback)
            {
                AppendLog("WMI-события недоступны: включён резервный опрос USB каждые 5 секунд.");
            }
            if (!string.IsNullOrWhiteSpace(EndpointProtectionEnvironment.Summary))
            {
                AppendLog(EndpointProtectionEnvironment.Summary);
            }
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Monitor start failed");
            MessageBox.Show(this, ex.Message, "Ошибка запуска мониторинга", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void StopMonitorButton_Click(object sender, RoutedEventArgs e)
    {
        _deviceChangeNotifier.Stop();
        _monitor.Stop();
        _unknownDeviceDetector = null;
        _vm.IsMonitoringActive = false;
        MonitorButton.IsEnabled = true;
        StopMonitorButton.IsEnabled = false;
        ShowActiveDevicesButton.IsEnabled = false;
        AppendLog("Live-мониторинг остановлен.");
        UpdateMonitorStatusBar(active: false);
    }

    /// <summary>
    /// Загружает базовую линию известных устройств из доказательной базы и
    /// помечает уже подключённые известные устройства как увиденные. Если
    /// в момент старта уже воткнуто неизвестное устройство — алерт придёт
    /// сразу, не дожидаясь переподключения.
    /// </summary>
    private async Task InitializeUnknownDeviceDetectorAsync()
    {
        try
        {
            var detector = await Task.Run(() =>
            {
                var baseline = _vm.Storage.ListKnownDeviceIdentities();
                return new UnknownDeviceDetector(baseline);
            }, _lifetimeCancellation.Token);

            await Dispatcher.InvokeAsync(() =>
            {
                _unknownDeviceDetector = detector;
                AppendLog(detector.BaselineSize == 0
                    ? "База известных устройств пуста: выполните полное сканирование, чтобы алерты о неизвестных устройствах заработали."
                    : "Контроль неизвестных устройств включён: база загружена из прошлых сканирований.");
            });
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            // Ожидаемое завершение при закрытии окна.
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Unknown device baseline load failed");
            await Dispatcher.InvokeAsync(() =>
                AppendLog($"Не удалось загрузить базу известных устройств: {ex.Message}"));
        }
    }

    /// <summary>
    /// Сверяет свежий снимок live-устройств с базовой линией и поднимает
    /// алерт по неизвестным. Вызывается из обновления окна активных устройств —
    /// отдельного опроса WMI не требуется.
    /// </summary>
    private void CheckForUnknownDevices(IReadOnlyList<LiveUsbDevice> devices)
    {
        var detector = _unknownDeviceDetector;
        if (detector is null || detector.BaselineSize == 0)
        {
            return;
        }

        var unknown = detector.DetectNew(devices);
        if (unknown.Count == 0)
        {
            return;
        }

        foreach (var device in unknown)
        {
            AppendLog($"ВНИМАНИЕ: подключено неизвестное устройство — {device.DeviceName} ({device.DeviceId}). В доказательной базе оно не встречалось.");
        }

        RegisterMonitorAlerts(unknown.Count);

        if (_unknownDeviceAlertWindow is not { IsVisible: true })
        {
            _unknownDeviceAlertWindow = new UnknownDeviceAlertWindow
            {
                Owner = this
            };
            _unknownDeviceAlertWindow.Closed += UnknownDeviceAlertWindow_Closed;
            _unknownDeviceAlertWindow.Show();
        }

        _unknownDeviceAlertWindow.AppendDevices(unknown);
    }

    /// <summary>Строка состояния: индикатор мониторинга и счётчик алертов за сегодня.</summary>
    private void UpdateMonitorStatusBar(bool active)
    {
        MonitorStatusDot.Fill = active
            ? (System.Windows.Media.Brush)FindResource("Ok")
            : (System.Windows.Media.Brush)FindResource("Stroke");
        MonitorStatusText.Text = active ? "Мониторинг активен" : "Мониторинг выключен";
    }

    private void RegisterMonitorAlerts(int count)
    {
        var today = DateOnly.FromDateTime(DateTime.Now);
        if (today != _alertsDay)
        {
            _alertsDay = today;
            _alertsToday = 0;
        }

        _alertsToday += count;
        MonitorAlertsText.Text = _alertsToday > 0 ? $"Алертов сегодня: {_alertsToday}" : "";
    }

    private void UnknownDeviceAlertWindow_Closed(object? sender, EventArgs e)
    {
        if (sender is UnknownDeviceAlertWindow window)
        {
            window.Closed -= UnknownDeviceAlertWindow_Closed;
        }

        _unknownDeviceAlertWindow = null;
    }

    private void ShowActiveDevicesButton_Click(object sender, RoutedEventArgs e)
    {
        ShowAndRefreshActiveDevicesWindow();
        AppendLog("Окно текущих USB/Type-C устройств открыто.");
    }

    private async void Monitor_RefreshRequested(object? sender, EventArgs e)
    {
        await RefreshActiveDevicesWindowAsync();
    }

    private async void Monitor_DeviceChanged(object? sender, string e)
    {
        try
        {
            await Dispatcher.InvokeAsync(() => AppendLog(e));
            await Task.Delay(800, _lifetimeCancellation.Token);
            await RefreshActiveDevicesWindowAsync();

            var shouldAutoScan = await Dispatcher.InvokeAsync(() =>
            {
                if (_vm.IsProcmonTracing
                    || DateTimeOffset.UtcNow - _lastAutoScanUtc < TimeSpan.FromSeconds(15))
                {
                    return false;
                }

                _lastAutoScanUtc = DateTimeOffset.UtcNow;
                return true;
            });
            if (shouldAutoScan)
            {
                await Dispatcher.InvokeAsync(
                    () => RunScanAsync("Автоснимок после изменения USB.")).Task.Unwrap();
            }
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            // Ожидаемое завершение фонового обработчика.
        }
    }

    private void ShowAndRefreshActiveDevicesWindow()
    {
        if (!IsActiveDevicesWindowOpen())
        {
            _activeDevicesWindow = new ActiveDevicesWindow
            {
                Owner = this
            };
            _activeDevicesWindow.Closed += ActiveDevicesWindow_Closed;
            _activeDevicesWindow.Show();
        }
        else
        {
            _activeDevicesWindow!.Activate();
            if (_activeDevicesWindow.WindowState == WindowState.Minimized)
            {
                _activeDevicesWindow.WindowState = WindowState.Normal;
            }
        }

        _ = RefreshActiveDevicesWindowAsync();
    }

    private bool IsActiveDevicesWindowOpen()
    {
        return _activeDevicesWindow is { IsVisible: true };
    }

    private void ActiveDevicesWindow_Closed(object? sender, EventArgs e)
    {
        if (sender is ActiveDevicesWindow window)
        {
            window.Closed -= ActiveDevicesWindow_Closed;
        }

        _activeDevicesWindow = null;
    }

    private async Task RefreshActiveDevicesWindowAsync()
    {
        // Снимок берётся, пока идёт мониторинг, даже если окно активных
        // устройств закрыто: алерт о неизвестном устройстве должен сработать
        // в любом случае. Состояние читается из ViewModel, а не из IsEnabled
        // кнопки — логика не должна зависеть от визуального состояния контрола.
        if (!_vm.IsMonitoringActive)
        {
            return;
        }

        if (!await _liveRefreshGate.WaitAsync(0))
        {
            return;
        }

        try
        {
            var devices = await Task.Run(
                _liveUsbSnapshotService.GetCurrentDevices,
                _lifetimeCancellation.Token);
            await Dispatcher.InvokeAsync(() =>
            {
                if (IsActiveDevicesWindowOpen())
                {
                    _activeDevicesWindow!.UpdateDevices(devices);
                }

                CheckForUnknownDevices(devices);
            });
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            // Ожидаемое завершение фонового обновления.
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Active USB snapshot failed");
            await Dispatcher.InvokeAsync(() => AppendLog($"Не удалось обновить окно текущих USB: {ex.Message}"));
        }
        finally
        {
            _liveRefreshGate.Release();
        }
    }
}
