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
    public string HardwareIds { get; set; } = "";

    private UsbDeviceRecord RecognitionRecord => new()
    {
        DeviceInstanceId = DeviceId, Vid = Vid, Pid = Pid, HardwareIds = HardwareIds,
        FriendlyName = DeviceName, Manufacturer = Manufacturer, Product = Product, Revision = Revision
    };

    public string DisplayName => UsbDeviceRecognition.DisplayName(RecognitionRecord);

    public string ManufacturerText => UsbDeviceRecognition.Manufacturer(RecognitionRecord);

    public string ModelText => UsbDeviceRecognition.Model(RecognitionRecord);

    public string VidPidText => UserDisplayText.VidPidCodes(Vid, Pid);

    public string StatusText => UserDisplayText.DeviceStatus(Status, DeviceId);

    public string LocationText => UserDisplayText.Location(Location, "");
}
