using System.Windows;

namespace UsbForensicAudit;

public partial class DeviceDetailsWindow : Window
{
    private readonly UsbDeviceRecord _device;
    private readonly AuditResult? _result;

    /// <summary>
    /// Результат сканирования нужен, чтобы показать историю работы на устройстве:
    /// следы лежат в общем списке улик, а не в самой записи устройства. Без него
    /// окно открывается, но кнопка истории отключена — это честнее, чем показать
    /// пустой список и оставить читателя думать, что действий не было.
    /// </summary>
    public DeviceDetailsWindow(UsbDeviceRecord device, AuditResult? result = null)
    {
        InitializeComponent();
        _device = device;
        _result = result;
        DataContext = device;
        DarkWindowChrome.Apply(this);

        if (result is null)
        {
            ActivityButton.IsEnabled = false;
            ActivityButton.ToolTip = "История доступна после сканирования.";
        }
    }

    private void ActivityButton_Click(object sender, RoutedEventArgs e)
    {
        if (_result is null)
        {
            return;
        }

        var history = DeviceActivityBuilder.Build(_device, _result);
        new DeviceActivityWindow(history) { Owner = this }.ShowDialog();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
