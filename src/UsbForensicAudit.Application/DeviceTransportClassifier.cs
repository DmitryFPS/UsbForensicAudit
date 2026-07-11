namespace UsbForensicAudit;

/// <summary>
/// Evidence-driven transport/topology classification. Unknown is preferred to
/// inferring an external device from a storage protocol or product name alone.
/// </summary>
public static class DeviceTransportClassifier
{
    private static readonly string[] ThunderboltMarkers =
    [
        "THUNDERBOLT", "TBT", "USB4", "Usb4HostRouter", "Usb4DeviceRouter", "Usb4P2PNetAdapter"
    ];

    private static readonly string[] VirtualMarkers =
    [
        "VMWARE", "VIRTUALBOX", "VBOX", "HYPER-V", "HYPERV", "VMBUS", "QEMU", "XEN"
    ];

    public static void ClassifyAll(IEnumerable<UsbDeviceRecord> devices)
    {
        var records = devices.ToArray();
        foreach (var device in records)
        {
            Classify(device);
        }

        foreach (var scsi in records.Where(x =>
                     x.DeviceInstanceId.StartsWith(@"SCSI\", StringComparison.OrdinalIgnoreCase)))
        {
            var bridge = records.FirstOrDefault(usb =>
                !ReferenceEquals(usb, scsi)
                && usb.DeviceInstanceId.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
                && IsSameTopology(scsi, usb));
            if (bridge is null)
            {
                continue;
            }

            if (scsi.Transport == "Unknown")
            {
                SetTransport(scsi, "UASP/SCSI", "Medium",
                    $"SCSI topology links to USB bridge {bridge.DeviceInstanceId}");
            }
            if (scsi.Connection == "Unknown")
            {
                SetConnection(scsi, "USB", "Medium",
                    $"linked USB bridge {bridge.DeviceInstanceId}");
            }
            if (scsi.Classification == "Unknown")
            {
                SetClassification(scsi, "External", "Medium",
                    "SCSI instance linked to a USB bridge by container/parent/topology");
            }
            ApplyPresentation(scsi);
        }
    }

    public static void Classify(UsbDeviceRecord device)
    {
        var text = EvidenceText(device);
        var id = device.DeviceInstanceId;

        Reset(device);
        ClassifyTransport(device, text, id);
        ClassifyConnection(device, text, id);
        ClassifyRole(device, text, id);

        if (device.Classification == "Unknown"
            && device.Connection is "USB" or "USB4/Thunderbolt" or "PCIe-tunneled candidate"
            && device.Transport != "Unknown")
        {
            SetClassification(device, "External", "Medium",
                $"external bus/topology evidence: {device.Connection}; transport={device.Transport}");
        }

        ApplyPresentation(device);
    }

    public static bool IsRelevantLiveCandidate(
        string pnpId,
        string service = "",
        string hardwareIds = "",
        string compatibleIds = "",
        string locationPaths = "",
        string name = "",
        string mediaType = "")
    {
        var text = Join(pnpId, service, hardwareIds, compatibleIds, locationPaths, name, mediaType);
        if (StartsWithAny(pnpId, @"USB\", @"USBSTOR\", @"SWD\WPDBUSENUM\", @"USB4\"))
        {
            return true;
        }

        if (service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase)
            || service.Equals("Usb4HostRouter", StringComparison.OrdinalIgnoreCase)
            || service.Equals("Usb4DeviceRouter", StringComparison.OrdinalIgnoreCase)
            || service.Equals("Usb4P2PNetAdapter", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (pnpId.StartsWith(@"PCI\", StringComparison.OrdinalIgnoreCase))
        {
            return ContainsAny(text, ThunderboltMarkers);
        }

        return ContainsAny(text, "WPDBUSENUM", "MTP", "PTP", "REMOVABLE", "EXTERNAL", "UASP")
               || ContainsAny(text, ThunderboltMarkers);
    }

    public static bool HasExternalTopologyEvidence(UsbDeviceRecord device)
    {
        var text = EvidenceText(device);
        return device.Service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase)
               || device.Connection is "USB" or "USB4/Thunderbolt" or "PCIe-tunneled candidate"
               || ContainsAny(text, "REMOVABLE", "EXTERNAL", "USBROOT", "USB(")
               || ContainsAny(text, ThunderboltMarkers);
    }

    public static bool IsReportable(UsbDeviceRecord device)
    {
        if (device.DeviceType.Equals("VolumeMapping", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (device.VisualCategory.Equals("UsbFlagsTrace", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (device.Classification is "Hub" or "BuiltIn" or "Composite" or "Virtual"
            && device.Connection == "USB")
        {
            return true;
        }

        if (device.DeviceInstanceId.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
            || device.DeviceInstanceId.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase)
            || device.DeviceInstanceId.StartsWith(@"SWD\WPDBUSENUM\", StringComparison.OrdinalIgnoreCase)
            || device.DeviceInstanceId.StartsWith(@"USB4\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (device.Classification == "External" && HasExternalTopologyEvidence(device))
        {
            return true;
        }

        return device.Transport == "UASP/SCSI"
               && HasExternalTopologyEvidence(device);
    }

    private static void ClassifyTransport(UsbDeviceRecord device, string text, string id)
    {
        if (device.Service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase))
        {
            SetTransport(device, "UASP/SCSI", "High", "Service=uaspstor");
        }
        else if (ContainsAny(text, "UASPSTOR", "UAS", "USB ATTACHED SCSI"))
        {
            SetTransport(device, "UASP/SCSI", "Medium", "hardware/compatible ID contains UASP marker");
        }
        else if (StartsWithAny(id, @"SWD\WPDBUSENUM\") || ContainsAny(text, "WPDBUSENUM", "MTP", "PTP"))
        {
            SetTransport(device, "MTP/PTP/WPD", "High", "WPD/MTP/PTP PnP evidence");
        }
        else if (id.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase)
                 || ContainsAny(device.HardwareIds, "USBSTOR"))
        {
            SetTransport(device, "MSC/USBSTOR", "High", "USBSTOR instance/hardware ID");
        }
        else if (id.StartsWith(@"SCSI\", StringComparison.OrdinalIgnoreCase)
                 && ContainsAny(text, "USB", "REMOVABLE", "EXTERNAL", "THUNDERBOLT", "USB4"))
        {
            SetTransport(device, "UASP/SCSI", "Medium", "SCSI instance with external/UASP topology evidence");
        }
        else if (id.StartsWith(@"USB4\", StringComparison.OrdinalIgnoreCase)
                 || ContainsAny(text, ThunderboltMarkers))
        {
            SetTransport(device, "USB4/Thunderbolt/PCIe-tunneled candidate", "Medium",
                "USB4/Thunderbolt service, ID, or topology marker");
        }
        else if (id.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase))
        {
            SetTransport(device, "USB", "High", "Enum/USB instance ID");
        }
    }

    private static void ClassifyConnection(UsbDeviceRecord device, string text, string id)
    {
        if (id.StartsWith(@"PCI\", StringComparison.OrdinalIgnoreCase)
            && ContainsAny(text, ThunderboltMarkers))
        {
            SetConnection(device, "PCIe-tunneled candidate", "Medium",
                "PCI instance has explicit USB4/Thunderbolt service, ID, or location marker");
        }
        else if (id.StartsWith(@"USB4\", StringComparison.OrdinalIgnoreCase)
                 || device.Service.StartsWith("Usb4", StringComparison.OrdinalIgnoreCase)
                 || ContainsAny(text, "THUNDERBOLT", "USB4"))
        {
            SetConnection(device, "USB4/Thunderbolt", "High",
                "USB4/Thunderbolt router/device evidence");
        }
        else if (StartsWithAny(id, @"USB\", @"USBSTOR\", @"SWD\WPDBUSENUM\")
                 || device.Service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase)
                 || ContainsAny(device.LocationPaths, "USBROOT", "USB("))
        {
            SetConnection(device, "USB", "High", "USB PnP/service/topology evidence");
        }
    }

    private static void ClassifyRole(UsbDeviceRecord device, string text, string id)
    {
        if (ContainsAny(text, VirtualMarkers))
        {
            SetClassification(device, "Virtual", "High", "virtualization vendor/bus marker");
            return;
        }

        if (ContainsAny(text, "ROOT_HUB", "ROOT HUB", "HOST CONTROLLER", "XHCI", "EHCI")
            || device.Service.Contains("USBXHCI", StringComparison.OrdinalIgnoreCase))
        {
            SetClassification(device, "Hub", "High", "USB root hub/host controller infrastructure marker");
            return;
        }

        if (ContainsAny(text, "HUB") || device.Service.Equals("usbhub", StringComparison.OrdinalIgnoreCase)
                                     || device.Service.Equals("usbhub3", StringComparison.OrdinalIgnoreCase))
        {
            SetClassification(device, "Hub", "High", "USB hub service/device marker");
            return;
        }

        if (id.Contains("&MI_", StringComparison.OrdinalIgnoreCase))
        {
            SetClassification(device, "Composite", "High", "USB composite interface MI_xx");
            return;
        }

        if (ContainsAny(text, "INTEGRATED", "BUILT-IN", "BUILT IN", "INTERNAL CAMERA", "WEBCAM")
            && !ContainsAny(text, "EXTERNAL"))
        {
            SetClassification(device, "BuiltIn", "Medium", "integrated/built-in device marker");
            return;
        }

        if (device.Connection == "USB4/Thunderbolt"
            && IsUsb4RouterService(device.Service))
        {
            SetClassification(device, "Hub", "High", $"USB4 infrastructure service={device.Service}");
            return;
        }

        if (device.Transport is "MSC/USBSTOR" or "MTP/PTP/WPD"
            || device.Service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase)
            || ContainsAny(text, "REMOVABLE", "EXTERNAL"))
        {
            SetClassification(device, "External",
                device.Service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase) ? "High" : "Medium",
                "removable/external transport evidence");
        }
    }

    private static void ApplyPresentation(UsbDeviceRecord device)
    {
        if (device.Classification == "Hub")
        {
            device.UserMeaning = "Инфраструктура шины: USB/USB4 hub, root hub или host/router controller; не пользовательский накопитель.";
        }
        else if (device.Classification == "Composite")
        {
            device.UserMeaning = "Интерфейс MI_xx составного USB-устройства; группируется с физическим parent-устройством.";
        }
        else if (device.Classification == "Virtual")
        {
            device.UserMeaning = "Виртуальное USB-устройство/шина гипервизора; не доказывает физическое подключение.";
        }
        else if (device.Classification == "BuiltIn")
        {
            device.UserMeaning = "Встроенное устройство внутренней USB-шины; сохранено в текущей области аудита и явно помечено.";
        }
        else if (device.Transport == "UASP/SCSI")
        {
            device.UserMeaning = "SCSI/UASP storage-запись включена только при наличии removable/external/UASP/topology evidence.";
        }

        if (IsReportable(device) && device.VisualCategory == "RelatedStorage")
        {
            device.VisualCategory = "RealUsb";
        }
    }

    private static string EvidenceText(UsbDeviceRecord device) => Join(
        device.DeviceInstanceId, device.Source, device.DeviceType, device.Service,
        device.HardwareIds, device.CompatibleIds, device.LocationInformation, device.LocationPaths,
        device.FriendlyName, device.Manufacturer, device.Product, device.RawJson);

    private static bool IsSameTopology(UsbDeviceRecord left, UsbDeviceRecord right)
    {
        if (!string.IsNullOrWhiteSpace(left.ContainerId)
            && left.ContainerId.Equals(right.ContainerId, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(left.ParentIdPrefix)
            && (right.ParentIdPrefix.Contains(left.ParentIdPrefix, StringComparison.OrdinalIgnoreCase)
                || right.Serial.Contains(left.ParentIdPrefix, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        var leftPath = left.LocationPaths.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault();
        var rightPath = right.LocationPaths.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault();
        return !string.IsNullOrWhiteSpace(leftPath)
               && !string.IsNullOrWhiteSpace(rightPath)
               && (leftPath.Contains(rightPath, StringComparison.OrdinalIgnoreCase)
                   || rightPath.Contains(leftPath, StringComparison.OrdinalIgnoreCase));
    }

    private static string Join(params string?[] values) =>
        string.Join(" ", values.Where(x => !string.IsNullOrWhiteSpace(x)));

    private static bool ContainsAny(string value, params string[] markers) =>
        markers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));

    private static bool StartsWithAny(string value, params string[] prefixes) =>
        prefixes.Any(prefix => value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

    private static bool IsUsb4RouterService(string service) =>
        service.Equals("Usb4HostRouter", StringComparison.OrdinalIgnoreCase)
        || service.Equals("Usb4DeviceRouter", StringComparison.OrdinalIgnoreCase)
        || service.Equals("Usb4P2PNetAdapter", StringComparison.OrdinalIgnoreCase);

    private static void Reset(UsbDeviceRecord d)
    {
        d.Transport = d.Connection = d.Classification = "Unknown";
        d.TransportConfidence = d.ConnectionConfidence = d.ClassificationConfidence = "Unknown";
        d.TransportProvenance.Clear();
        d.ConnectionProvenance.Clear();
        d.ClassificationProvenance.Clear();
    }

    private static void SetTransport(UsbDeviceRecord d, string value, string confidence, string evidence)
    {
        d.Transport = value;
        d.TransportConfidence = confidence;
        d.TransportProvenance.Add(evidence);
    }

    private static void SetConnection(UsbDeviceRecord d, string value, string confidence, string evidence)
    {
        d.Connection = value;
        d.ConnectionConfidence = confidence;
        d.ConnectionProvenance.Add(evidence);
    }

    private static void SetClassification(UsbDeviceRecord d, string value, string confidence, string evidence)
    {
        d.Classification = value;
        d.ClassificationConfidence = confidence;
        d.ClassificationProvenance.Add(evidence);
    }
}
