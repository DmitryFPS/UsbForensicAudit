using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace UsbForensicAudit;

/// <summary>
/// Панель досье справа от таблицы устройств: выделил строку — сразу видишь
/// ключевые поля без двойного клика и отдельного окна. Набор полей — тот же
/// единый источник, что у HTML- и PDF-отчётов (DeviceCardModel), поэтому
/// панель не разойдётся с отчётами при добавлении полей.
/// </summary>
public partial class MainWindow
{
    private void DevicesGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateDeviceSelectionActions();
        if (DevicesGrid.SelectedItems.Count > 1)
        {
            HideDeviceDetail();
            return;
        }
        if (DevicesGrid.SelectedItem is not UsbDeviceRecord device)
        {
            HideDeviceDetail();
            return;
        }

        DeviceDetailTitle.Text = device.DisplayName;

        var badge = device.PolicyBadgeText;
        DeviceDetailPolicy.Visibility = string.IsNullOrEmpty(badge) ? Visibility.Collapsed : Visibility.Visible;
        DeviceDetailPolicy.Text = badge;
        DeviceDetailPolicy.Foreground = device.PolicyDecision switch
        {
            DevicePolicyDecision.Blocked => (Brush)FindResource("Danger"),
            DevicePolicyDecision.Unlisted => (Brush)FindResource("Warn"),
            DevicePolicyDecision.Approved => (Brush)FindResource("Ok"),
            _ => (Brush)FindResource("TextMuted")
        };

        DeviceDetailFields.Text = string.Join(
            "\n",
            DeviceCardModel.FieldsOf(device)
                .Where(field => !string.IsNullOrWhiteSpace(field.Value))
                .Select(field => $"{field.Label}: {field.Value}"));

        PopulateDeviceEvents(device);

        DeviceDetailPanel.Visibility = Visibility.Visible;
        DeviceDetailColumn.Width = new GridLength(360);
    }

    /// <summary>
    /// Мини-лента: последние события, где упомянуто это устройство. Совпадение
    /// ищется по подтверждённым идентификаторам устройства/тома. Общее имя
    /// модели и переиспользуемая буква диска не приписывают событие этой вещи.
    /// </summary>
    private void PopulateDeviceEvents(UsbDeviceRecord device)
    {
        var evidence = _vm.LastResult?.Evidence;
        if (evidence is null)
        {
            DeviceDetailEventsHeader.Visibility = Visibility.Collapsed;
            DeviceDetailEvents.ItemsSource = null;
            return;
        }

        var keys = DeviceLinkKeys.Build(device, _vm.LastResult!.Devices);

        var events = evidence
            .Where(x => keys.Match(x) is { Confidence: "High" })
            .OrderByDescending(x => x.TimestampUtc)
            .Take(10)
            .Select(x => $"{x.TimestampText} — {x.SummaryText}")
            .ToArray();

        DeviceDetailEventsHeader.Visibility = events.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        DeviceDetailEvents.ItemsSource = events;
    }

    private void CloseDeviceDetailButton_Click(object sender, RoutedEventArgs e) => HideDeviceDetail();

    private void HideDeviceDetail()
    {
        DeviceDetailPanel.Visibility = Visibility.Collapsed;
        DeviceDetailColumn.Width = new GridLength(0);
    }

    /// <summary>Полное досье — то же окно, что открывалось двойным кликом.</summary>
    private void OpenDeviceDetailsButton_Click(object sender, RoutedEventArgs e)
    {
        if (DevicesGrid.SelectedItem is not UsbDeviceRecord device)
        {
            return;
        }

        var detailsWindow = new DeviceDetailsWindow(device, _vm.LastResult)
        {
            Owner = this
        };

        detailsWindow.ShowDialog();
    }
}
