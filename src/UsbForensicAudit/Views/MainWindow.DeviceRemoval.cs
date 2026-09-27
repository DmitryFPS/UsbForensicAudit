using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;

namespace UsbForensicAudit;

public partial class MainWindow
{
    private readonly DeviceVidPidGrouping _deviceGrouping = new();
    private bool _deviceRemovalActive;
    private bool _deviceActionsBusy;

    private void UpdateDeviceSelectionActions()
    {
        if (PreviewDeviceRemovalButton is null || DevicesGrid is null)
        {
            return;
        }

        var count = DevicesGrid.SelectedItems.Count;
        var ready = !_deviceActionsBusy && _vm.LastResult is not null && count > 0;
        PreviewDeviceRemovalButton.IsEnabled = ready && !_vm.LastResult!.IsOfflineSource;
        DeviceSelectionText.Text = count == 0 ? "Выберите записи галочками или с Ctrl / Shift" : $"Выбрано записей: {count}";
    }

    private void ExpandDeviceGroups_Click(object sender, RoutedEventArgs e) => _deviceGrouping.SetExpanded(true);
    private void CollapseDeviceGroups_Click(object sender, RoutedEventArgs e) => _deviceGrouping.SetExpanded(false);
    private void ClearDeviceSelection_Click(object sender, RoutedEventArgs e) => DevicesGrid.UnselectAll();
    private void SelectDeviceList_Click(object sender, RoutedEventArgs e) => DevicesGrid.SelectAll();

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
        var groups = _devicesView.Groups?.Cast<System.Windows.Data.CollectionViewGroup>()
            .Count(x => ((DeviceDisplayGroup)x.Name).IsGrouped) ?? 0;
        DeviceListSummaryText.Text = $"Показано записей: {_devicesView.Cast<object>().Count()}. Групп VID/PID: {groups}. Одиночные записи — внизу списка.";
        UpdateDeviceSelectionActions();
    }

    private void DeviceSearchBox_TextChanged(object sender, TextChangedEventArgs e) => RefreshDeviceGrouping();

    private async void PreviewDeviceRemovalButton_Click(object sender, RoutedEventArgs e)
    {
        var source = _vm.LastResult;
        var selected = DevicesGrid.SelectedItems.OfType<UsbDeviceRecord>().ToArray();
        if (source is null || selected.Length == 0)
        {
            MessageBox.Show(this, "Выберите одно или несколько устройств галочками в таблице.", "Удаление устройств");
            return;
        }
        if (!await _exclusiveOperation.WaitAsync(0))
        {
            AppendLog("Дождитесь завершения текущей операции перед удалением.");
            return;
        }
        try
        {
            _deviceRemovalActive = true;
            SetBusy(true);
            var service = new DeviceRemovalService(new WindowsDeviceRemovalPlatform(_vm.Storage.DataDirectory), _vm.Storage);
            StatusText.Text = "Проверка выбранных экземпляров Windows...";
            var plan = await Task.Run(() => service.Preview(source, selected), _lifetimeCancellation.Token);
            var preview = new DeviceRemovalPreviewWindow(plan) { Owner = this };
            if (preview.ShowDialog() != true)
            {
                return;
            }

            var progress = new Progress<string>(message => { StatusText.Text = message; AppendLog(message); });
            var result = await Task.Run(() => service.ExecuteAsync(plan, progress, _lifetimeCancellation.Token));
            var saved = await Task.Run(() => _vm.Storage.Load(source.SessionId));
            if (saved is not null)
            {
                _vm.LastResult = saved;
                BindResult(saved);
            }
            AppendLog(result.Summary);
            AppendLog($"Копии и протокол удаления: {result.BackupDirectory}");
            if (result.DatabaseRemoval is { RemovedCount: > 0 } databaseRemoval)
            {
                AppendLog($"Резервная копия карточек базы: {databaseRemoval.BackupDirectory}");
            }
            MessageBox.Show(this, result.Summary + Environment.NewLine
                + "Результат относится к записям подтверждённого плана. Общие журналы Windows и неподдерживаемые источники не очищались."
                + Environment.NewLine + "Копии и протокол: " + result.BackupDirectory,
                "Результат удаления", MessageBoxButton.OK,
                result.FailedCount > 0 || result.SkippedCount > 0 || result.DatabaseError.Length > 0 || result.ProtocolError.Length > 0
                    ? MessageBoxImage.Warning : MessageBoxImage.Information);
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
