namespace UsbForensicAudit;

/// <summary>
/// Порт получения списка устройств, подключённых к системе в момент сканирования.
/// Реализация живёт в инфраструктуре (WMI); слой Application зависит только от абстракции.
/// </summary>
public interface IConnectedDeviceProbe
{
    ConnectedDeviceIndex Capture();
}

/// <summary>
/// Пустая проба: используется, когда данные о живых подключениях недоступны (например, в тестах).
/// </summary>
public sealed class NullConnectedDeviceProbe : IConnectedDeviceProbe
{
    public static NullConnectedDeviceProbe Instance { get; } = new();

    public ConnectedDeviceIndex Capture() => ConnectedDeviceIndex.Empty;
}
