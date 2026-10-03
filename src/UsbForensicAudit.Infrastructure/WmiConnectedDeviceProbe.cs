namespace UsbForensicAudit;

/// <summary>Present-only PnP snapshot, with WMI fallback and explicit Bluetooth state.</summary>
public sealed class WmiConnectedDeviceProbe : IConnectedDeviceProbe
{
    public ConnectedDeviceIndex Capture() => WindowsPnpSnapshot.Capture().ToIndex();
}
