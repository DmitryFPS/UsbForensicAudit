using System.Collections.ObjectModel;
using System.Media;
using System.Windows;

namespace UsbForensicAudit;

/// <summary>
/// Немодальный алерт резидентного мониторинга: показывается поверх остальных
/// окон при подключении устройства, которого нет в доказательной базе.
/// Немодальность важна — алерт не должен блокировать идущее сканирование,
/// а новые неизвестные устройства дописываются в уже открытое окно.
/// </summary>
public partial class UnknownDeviceAlertWindow : Window
{
    private readonly ObservableCollection<LiveUsbDevice> _unknownDevices = [];

    public ObservableCollection<LiveUsbDevice> UnknownDevices => _unknownDevices;

    public UnknownDeviceAlertWindow()
    {
        InitializeComponent();
        DataContext = this;
        DarkWindowChrome.Apply(this);
    }

    /// <summary>
    /// Добавляет неизвестные устройства в список, обновляет подзаголовок и
    /// привлекает внимание: активирует окно и проигрывает системный звук.
    /// </summary>
    public void AppendDevices(IReadOnlyList<LiveUsbDevice> devices)
    {
        foreach (var device in devices)
        {
            var alreadyShown = _unknownDevices.Any(x =>
                x.DeviceId.Equals(device.DeviceId, StringComparison.OrdinalIgnoreCase));
            if (!alreadyShown)
            {
                device.ConnectedAtText = DateDisplay.FormatMoscow(DateTimeOffset.UtcNow);
                _unknownDevices.Add(device);
            }
        }

        SubtitleText.Text = _unknownDevices.Count == 1
            ? "Устройство не встречалось ни в одном из прошлых сканирований этой машины. Проверьте, ожидалось ли его подключение."
            : $"Неизвестных устройств за время мониторинга: {_unknownDevices.Count}. Ни одно из них не встречалось в прошлых сканированиях.";

        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        Activate();
        try
        {
            SystemSounds.Exclamation.Play();
        }
        catch
        {
            // Отсутствие звука не должно ломать алерт.
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
