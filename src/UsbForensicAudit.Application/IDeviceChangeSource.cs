namespace UsbForensicAudit;

/// <summary>
/// Источник системных уведомлений об изменении состава устройств.
/// Позволяет инфраструктурному монитору (WMI) принимать события от
/// presentation-специфичных механизмов (например, WM_DEVICECHANGE через
/// окно WPF), не зная о WPF-типах.
/// </summary>
public interface IDeviceChangeSource
{
    /// <summary>Возникает при подключении или отключении устройства; аргумент — человекочитаемое описание события.</summary>
    public event EventHandler<string>? DeviceChanged;
}
