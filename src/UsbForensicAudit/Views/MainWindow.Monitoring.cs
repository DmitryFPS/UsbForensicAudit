using System.Windows;

namespace UsbForensicAudit;

/// <summary>
/// Live-мониторинг USB: подписка на события Windows, окно текущих устройств,
/// автоснимок после изменения состава USB. Отдельный файл — мониторинг живёт
/// по своим событиям и не пересекается с ручными операциями пользователя.
/// </summary>
public partial class MainWindow
{
    private void MonitorButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _deviceChangeNotifier.Start();
            _monitor.Start();
            ShowAndRefreshActiveDevicesWindow();
            MonitorButton.IsEnabled = false;
            StopMonitorButton.IsEnabled = true;
            ShowActiveDevicesButton.IsEnabled = true;
            AppendLog("Live-мониторинг запущен. Обновление идёт по событиям Windows, без постоянного опроса каждые 2 секунды.");
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
        MonitorButton.IsEnabled = true;
        StopMonitorButton.IsEnabled = false;
        ShowActiveDevicesButton.IsEnabled = false;
        AppendLog("Live-мониторинг остановлен.");
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
        var shouldRefresh = await Dispatcher.InvokeAsync(
            () => StopMonitorButton.IsEnabled && IsActiveDevicesWindowOpen());
        if (!shouldRefresh)
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
