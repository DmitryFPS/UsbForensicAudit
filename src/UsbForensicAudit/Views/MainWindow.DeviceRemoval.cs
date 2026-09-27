using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;

namespace UsbForensicAudit;

public partial class MainWindow
{
    private readonly DeviceVidPidGrouping _deviceGrouping = new();
    private bool _deviceRemovalActive;

    private void RefreshDeviceGrouping()
    {
        if (_devicesView is null)
        {
            return;
        }

        _deviceGrouping.Reset(_devices.Where(x => FilterDevice(x)),
            !string.IsNullOrWhiteSpace(DeviceSearchBox?.Text));
        _devicesView.Refresh();
        UpdateDeviceCount();
    }

    private void DeviceSearchBox_TextChanged(object sender, TextChangedEventArgs e) => RefreshDeviceGrouping();

    private async void PreviewDeviceRemovalButton_Click(object sender, RoutedEventArgs e)
    {
        var source = _vm.LastResult;
        var selected = DevicesGrid.SelectedItems.OfType<UsbDeviceRecord>().ToArray();
        if (source is null || selected.Length == 0)
        {
            MessageBox.Show(this, "Выберите одно или несколько устройств в таблице (Ctrl или Shift).", "Удаление устройств");
            return;
        }
        if (!await _exclusiveOperation.WaitAsync(0))
        {
            AppendLog("Дождитесь завершения текущей операции перед удалением.");
            return;
        }
        var removalStarted = false;
        try
        {
            _deviceRemovalActive = true;
            SetBusy(true);
            var service = new DeviceRemovalService(new WindowsDeviceRemovalPlatform(_vm.Storage.DataDirectory));
            StatusText.Text = "Проверка выбранных экземпляров Windows...";
            var plan = await Task.Run(() => service.Preview(source, selected), _lifetimeCancellation.Token);
            var preview = new DeviceRemovalPreviewWindow(plan) { Owner = this };
            if (preview.ShowDialog() != true)
            {
                return;
            }

            removalStarted = true;
            var progress = new Progress<string>(message => { StatusText.Text = message; AppendLog(message); });
            var result = await Task.Run(() => service.ExecuteAsync(plan, progress, _lifetimeCancellation.Token));
            AppendLog(result.Summary);
            AppendLog($"Копии и протокол удаления: {result.BackupDirectory}");
            MessageBox.Show(this, result.Summary + Environment.NewLine + "Копии и протокол: " + result.BackupDirectory,
                "Результат удаления", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Device removal");
            AppendLog($"Удаление: {ex.Message}");
            MessageBox.Show(this, ex.Message, "Удаление устройств", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _deviceRemovalActive = false;
            SetBusy(false);
            StatusText.Text = "Готово";
            _exclusiveOperation.Release();
        }
        if (removalStarted)
        {
            await RunScanAsync("Повторный поиск после удаления экземпляров Windows.");
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (_deviceRemovalActive)
        {
            e.Cancel = true;
            AppendLog("Дождитесь завершения проверки или удаления устройств перед закрытием окна.");
        }
        base.OnClosing(e);
    }
}
