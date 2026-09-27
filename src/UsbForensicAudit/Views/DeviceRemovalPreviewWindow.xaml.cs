using System.Windows;

namespace UsbForensicAudit;

public partial class DeviceRemovalPreviewWindow : Window
{
    public DeviceRemovalPreviewWindow(DeviceRemovalPlan plan)
    {
        InitializeComponent();
        DarkWindowChrome.Apply(this);
        PlanGrid.ItemsSource = plan.Items;
        SummaryText.Text = $"Можно удалить: {plan.RemovableCount}. Только просмотр: {plan.ProtectedCount}.";
        RemoveButton.Content = $"Удалить экземпляры: {plan.RemovableCount}";
        RemoveButton.IsEnabled = plan.RemovableCount > 0;
    }

    private void RemoveButton_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}
