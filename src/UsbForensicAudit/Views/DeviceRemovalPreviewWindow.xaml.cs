using System.Windows;

namespace UsbForensicAudit;

public partial class DeviceRemovalPreviewWindow : Window
{
    private readonly DeviceRemovalPlan _plan;
    public DeviceRemovalPreviewWindow(DeviceRemovalPlan plan)
    {
        _plan = plan;
        InitializeComponent();
        DarkWindowChrome.Apply(this);
        ShowProtected.IsChecked = plan.ProtectedCount > 0;
        ShowProtected.Content = $"Показать недоступные для удаления записи ({plan.ProtectedCount})";
        RefreshItems();
        SummaryText.Text = $"Удаление из Windows: {plan.RemovableCount}. Не будут удалены: {plan.ProtectedCount}."
            + (plan.ProtectedCount > 0 ? " Очистка будет частичной." : "");
        RemoveButton.Content = $"Удалить из Windows: {plan.RemovableCount}";
        RemoveButton.IsEnabled = plan.RemovableCount > 0;
    }

    private void ShowProtected_Changed(object sender, RoutedEventArgs e) => RefreshItems();

    private void RefreshItems()
    {
        if (PlanGrid is null)
        {
            return;
        }

        PlanGrid.ItemsSource = _plan.Items.Where(x => x.CanRemove || ShowProtected.IsChecked == true)
            .OrderByDescending(x => x.CanRemove).ToArray();
    }

    private void RemoveButton_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}
