namespace UsbForensicAudit;

public sealed class LiveUsbDevice
{
    public string ConnectedAtText { get; set; } = "";
    public string DeviceName { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string Vid { get; set; } = "";
    public string Pid { get; set; } = "";
    public string Location { get; set; } = "";
    public string Status { get; set; } = "";
    public string StableKey { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string Product { get; set; } = "";
    public string Revision { get; set; } = "";

    public string ManufacturerText => UserDisplayText.ManufacturerName(Manufacturer, DeviceName, Vid);

    public string ModelText => UserDisplayText.ModelName(Product, DeviceName, Revision, Pid);

    public string VidPidText => UserDisplayText.VidPidCodes(Vid, Pid);

    public string StatusText => UserDisplayText.DeviceStatus(Status, DeviceId);

    public string LocationText => UserDisplayText.Location(Location, "");
}
