using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;

namespace UsbForensicAudit;

public partial class ActiveDevicesWindow : Window
{
    private readonly ObservableCollection<LiveUsbDevice> _activeDevices = [];
    private readonly Dictionary<string, string> _firstSeenTextByStableKey = new(StringComparer.OrdinalIgnoreCase);
    private bool _hasInitialSnapshot;

    public ObservableCollection<LiveUsbDevice> ActiveDevices => _activeDevices;

    public ActiveDevicesWindow()
    {
        InitializeComponent();
        DataContext = this;
        DarkWindowChrome.Apply(this);
    }

    public void UpdateDevices(IEnumerable<LiveUsbDevice> devices)
    {
        var selectedKey = (ActiveDevicesGrid.SelectedItem as LiveUsbDevice)?.StableKey;
        var incoming = devices.ToArray();
        var incomingByKey = incoming.ToDictionary(GetStableKey, device => device, StringComparer.OrdinalIgnoreCase);

        for (var index = _activeDevices.Count - 1; index >= 0; index--)
        {
            if (!incomingByKey.ContainsKey(GetStableKey(_activeDevices[index])))
            {
                _activeDevices.RemoveAt(index);
            }
        }

        foreach (var device in incoming)
        {
            var key = GetStableKey(device);
            var existing = _activeDevices.FirstOrDefault(x => GetStableKey(x).Equals(key, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                if (!_firstSeenTextByStableKey.TryGetValue(key, out var firstSeenText))
                {
                    firstSeenText = _hasInitialSnapshot
                        ? DateDisplay.FormatMoscow(DateTimeOffset.UtcNow)
                        : "уже было подключено";
                    _firstSeenTextByStableKey[key] = firstSeenText;
                }

                device.ConnectedAtText = firstSeenText;
                _activeDevices.Add(device);
                continue;
            }

            CopyDeviceFields(device, existing);
        }

        foreach (var oldKey in _firstSeenTextByStableKey.Keys.ToArray())
        {
            if (!incomingByKey.ContainsKey(oldKey))
            {
                _firstSeenTextByStableKey.Remove(oldKey);
            }
        }

        _hasInitialSnapshot = true;
        RestoreSelection(selectedKey);
    }

    private void RestoreSelection(string? selectedKey)
    {
        if (string.IsNullOrWhiteSpace(selectedKey))
        {
            return;
        }

        var selected = _activeDevices.FirstOrDefault(x => GetStableKey(x).Equals(selectedKey, StringComparison.OrdinalIgnoreCase));
        if (selected is null)
        {
            return;
        }

        if (!ReferenceEquals(ActiveDevicesGrid.SelectedItem, selected))
        {
            ActiveDevicesGrid.SelectedItem = selected;
        }
    }

    private static string GetStableKey(LiveUsbDevice device)
    {
        return string.IsNullOrWhiteSpace(device.StableKey)
            ? LiveDeviceIdentity.NormalizeDeviceId(device.DeviceId)
            : device.StableKey;
    }

    private static void CopyDeviceFields(LiveUsbDevice source, LiveUsbDevice target)
    {
        target.DeviceName = source.DeviceName;
        target.DeviceId = source.DeviceId;
        target.Vid = source.Vid;
        target.Pid = source.Pid;
        target.Location = source.Location;
        target.Status = source.Status;
        target.Manufacturer = source.Manufacturer;
        target.Product = source.Product;
        target.Revision = source.Revision;
    }
}
