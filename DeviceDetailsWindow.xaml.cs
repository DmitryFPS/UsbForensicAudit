using System.Windows;

namespace UsbForensicAudit;

public partial class DeviceDetailsWindow : Window
{
    public DeviceDetailsWindow(UsbDeviceRecord device)
    {
        InitializeComponent();
        DataContext = device;
        DarkWindowChrome.Apply(this);
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
