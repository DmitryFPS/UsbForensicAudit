using System.Text.RegularExpressions;

namespace UsbForensicAudit;

/// <summary>
/// Evidence-driven transport/topology classification. Unknown is preferred to
/// inferring an external device from a storage protocol or product name alone.
/// </summary>
public static partial class DeviceTransportClassifier
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
            var bridges = records.Where(usb =>
                !ReferenceEquals(usb, scsi)
                && usb.DeviceInstanceId.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
                && usb.Classification is not "Hub" and not "Virtual"
                && (scsi.Classification != "BuiltIn" || usb.Transport is "MSC/USBSTOR" or "UASP/SCSI"
                    || DeviceLiveMatcher.PnpIdsMatch(scsi.ParentDeviceInstanceId, usb.DeviceInstanceId))
                && IsSameTopology(scsi, usb)).DistinctBy(x => x.DeviceInstanceId, StringComparer.OrdinalIgnoreCase).ToArray();
            if (bridges.Length != 1)
            {
                continue;
            }
            var bridge = bridges[0];

            if (scsi.Transport is "Unknown" or "Internal Disk" or "Internal NVMe")
            {
                SetTransport(scsi, "UASP/SCSI", "Medium",
                    $"SCSI topology links to USB bridge {bridge.DeviceInstanceId}");
            }
            if (scsi.Connection == "Unknown")
            {
                SetConnection(scsi, "USB", "Medium",
                    $"linked USB bridge {bridge.DeviceInstanceId}");
            }
            if (scsi.Classification is "Unknown" or "BuiltIn")
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
        if (BluetoothCacheIdentity.AddressFromPath(id).Length > 0)
        {
            SetTransport(device, "Bluetooth", "High", "Addressed BTHPORT device cache");
            SetConnection(device, "Bluetooth", "High", "BTHPORT device cache");
            SetClassification(device, "External", "High", "Remote Bluetooth address");
            device.VisualCategory = "HistoricalResidual";
            device.DeviceKind = DeviceKindResolver.RegistryTrace;
            return;
        }
        if (DeviceComposition.IsVolumeMetadata(device))
        {
            device.VisualCategory = "SupportArtifact";
            device.DeviceKind = DeviceKindResolver.RegistryTrace;
            return;
        }
        if (IsVirtualStorageDevice(device, text, id))
        {
            SetTransport(device, "Virtual Disk", "High", "virtual/hypervisor disk image");
            SetClassification(device, "Virtual", "High", "virtual/hypervisor storage");
            ApplyPresentation(device);
            return;
        }

        if (SetupApiDeviceRelations.IsStorageUsbParent(id, device.ParentDeviceInstanceId))
        {
            SetTransport(device, "UASP/SCSI", "High", "Exact USB parent: " + device.ParentDeviceInstanceId);
            SetConnection(device, "USB", "High", "Kernel-PnP parent device instance");
            SetClassification(device, "External", "High", "SCSI storage with a confirmed USB parent");
            ApplyPresentation(device);
            return;
        }

        if (IsInternalFixedStorage(device, text, id))
        {
            if (IsInternalNvmeStorage(device, text, id))
            {
                SetTransport(device, "Internal NVMe", "High", "SCSI/NVMe stack without external USB/UASP topology");
            }
            else
            {
                SetTransport(device, "Internal Disk", "High", "SCSI/GenDisk stack without external USB/UASP topology");
            }

            SetClassification(device, "BuiltIn", "High", "internal fixed disk without external USB/UASP topology");
            ApplyPresentation(device);
            return;
        }

        ClassifyTransport(device, text, id);
        ClassifyConnection(device, text, id);
        ClassifyRole(device, RoleEvidenceText(device), id);

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
        if (BluetoothEnumeratorId.DeviceAddress(pnpId).Length > 0)
        {
            return true;
        }
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

        return DeviceMarkerText.ContainsAnyMarker(text, "WPDBUSENUM", "MTP", "PTP", "REMOVABLE", "EXTERNAL")
               || ContainsUaspMarker(text)
               || ContainsAny(text, ThunderboltMarkers);
    }

    public static bool IsBuiltinStorageLiveCandidate(
        string pnpId,
        string service = "",
        string hardwareIds = "",
        string compatibleIds = "",
        string locationPaths = "",
        string name = "",
        string mediaType = "")
    {
        if (!pnpId.StartsWith(@"SCSI\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var stub = new UsbDeviceRecord
        {
            DeviceInstanceId = pnpId,
            Service = service,
            HardwareIds = hardwareIds,
            CompatibleIds = compatibleIds,
            LocationPaths = locationPaths,
            FriendlyName = name
        };

        if (!IsInternalFixedStorage(stub) && !IsInternalNvmeStorage(stub))
        {
            return false;
        }

        return mediaType.Length == 0
               || mediaType.Contains("Fixed", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsInternalFixedStorage(UsbDeviceRecord device, string? evidenceText = null, string? deviceInstanceId = null)
    {
        if (IsVirtualStorageDevice(device, evidenceText, deviceInstanceId))
        {
            return false;
        }

        if (IsInternalNvmeStorage(device, evidenceText, deviceInstanceId))
        {
            return true;
        }

        var id = deviceInstanceId ?? device.DeviceInstanceId;
        var text = evidenceText ?? EvidenceText(device);
        if (!id.StartsWith(@"SCSI\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!device.Service.Equals("disk", StringComparison.OrdinalIgnoreCase)
            || device.Service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase)
            || HasExternalTopologyEvidence(device))
        {
            return false;
        }

        return ContainsAny(text, "GENDISK")
               && !ScsiHasExternalBusEvidence(text, id);
    }

    public static bool IsVirtualStorageDevice(UsbDeviceRecord device, string? evidenceText = null, string? deviceInstanceId = null)
    {
        var id = deviceInstanceId ?? device.DeviceInstanceId;
        var text = evidenceText ?? EvidenceText(device);
        return ContainsAny(text, VirtualMarkers)
               || ContainsAny(id, @"VEN_MSFT&PROD_VIRTUAL", "VEN_VMWARE", "VIRTUAL_DISK", "VBOXHD");
    }

    public static bool IsInternalNvmeStorage(UsbDeviceRecord device, string? evidenceText = null, string? deviceInstanceId = null)
    {
        var id = deviceInstanceId ?? device.DeviceInstanceId;
        var text = evidenceText ?? EvidenceText(device);
        if (!id.StartsWith(@"SCSI\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var isNvmeVendor = ContainsAny(id, @"VEN_NVME", "DISKNVME", "NVME____")
                            || ContainsAny(text, @"VEN_NVME", "DISKNVME", "NVME____");
        var usesDiskStack = device.Service.Equals("disk", StringComparison.OrdinalIgnoreCase)
                            || device.Service.Equals("stornvme", StringComparison.OrdinalIgnoreCase);
        if (!isNvmeVendor || !usesDiskStack)
        {
            return false;
        }

        return !device.Service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase)
               && !HasExternalTopologyEvidence(device);
    }

    public static bool HasExternalTopologyEvidence(UsbDeviceRecord device)
    {
        var text = EvidenceText(device);
        return device.Service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase)
               || SetupApiDeviceRelations.IsStorageUsbParent(device.DeviceInstanceId, device.ParentDeviceInstanceId)
               || device.Connection is "USB" or "USB4/Thunderbolt" or "PCIe-tunneled candidate"
               || ContainsAny(text, "REMOVABLE", "EXTERNAL", "USBROOT", "USB(")
               || ContainsAny(text, ThunderboltMarkers);
    }

    public static bool IsReportable(UsbDeviceRecord device)
    {
        if (DeviceComposition.IsVolumeMetadata(device))
        {
            return false;
        }

        if (device.VisualCategory.Equals("UsbFlagsTrace", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (device.Classification is "Hub" or "Composite" or "Virtual"
            && device.Connection == "USB")
        {
            return true;
        }

        if (device.Classification == "BuiltIn"
            && device.Connection == "USB"
            && device.Transport is not "Internal NVMe" and not "Internal Disk")
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
        if (BluetoothEnumeratorId.IsPairedDeviceRecord(id) || BluetoothEnumeratorId.IsServiceRecord(id))
        {
            SetTransport(device, "Bluetooth", "High", "Bluetooth enumerator instance ID");
        }
        else if (DeviceComposition.IsWpdUsbStorage(device))
        {
            SetTransport(device, "MSC/USBSTOR", "High", "WPD wrapper contains a USBSTOR device path");
        }
        else if (device.Service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase))
        {
            SetTransport(device, "UASP/SCSI", "High", "Service=uaspstor");
        }
        else if (ContainsUaspMarker(text))
        {
            SetTransport(device, "UASP/SCSI", "Medium", "hardware/compatible ID contains UASP marker");
        }
        else if (device.Service.Equals("USBSTOR", StringComparison.OrdinalIgnoreCase)
                 || id.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase)
                 || ContainsAny(device.HardwareIds, "USBSTOR")
                 || Regex.IsMatch(device.CompatibleIds, @"USB\\Class_08(?:&|;|\s|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            SetTransport(device, "MSC/USBSTOR", "High", "USB storage service, instance or compatible class");
        }
        else if (StartsWithAny(id, @"SWD\WPDBUSENUM\")
                 || DeviceMarkerText.ContainsAnyMarker(text, "WPDBUSENUM", "MTP", "PTP"))
        {
            SetTransport(device, "MTP/PTP/WPD", "High", "WPD/MTP/PTP PnP evidence");
        }
        else if (id.StartsWith(@"SCSI\", StringComparison.OrdinalIgnoreCase)
                 && ScsiHasExternalBusEvidence(text, id))
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
        var usbNode = StartsWithAny(id, @"USB\", @"USBSTOR\") || DeviceComposition.IsWpdUsbStorage(device);
        var usbParent = StartsWithAny(device.ParentDeviceInstanceId, @"USB\", @"USBSTOR\");
        var bluetoothParent = BluetoothEnumeratorId.DeviceAddress(device.ParentDeviceInstanceId).Length > 0;
        var usbAlias = device.IdentityAliases.Any(alias => StartsWithAny(alias, @"USB\", @"USBSTOR\"));
        var bluetoothAlias = device.IdentityAliases.Any(alias => BluetoothEnumeratorId.DeviceAddress(alias).Length > 0);
        if (device.Transport == "Bluetooth"
            || (!usbNode && !usbParent && (bluetoothParent || (bluetoothAlias && !usbAlias))))
        {
            SetConnection(device, "Bluetooth", "High", "Bluetooth enumerator instance ID");
        }
        else if (id.StartsWith(@"PCI\", StringComparison.OrdinalIgnoreCase)
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
        else if (usbNode || usbParent || (usbAlias && !bluetoothAlias)
                 || device.Service.Equals("uaspstor", StringComparison.OrdinalIgnoreCase)
                 || ContainsAny(device.LocationPaths, "USBROOT", "USB("))
        {
            SetConnection(device, "USB", "High", "USB PnP/service/topology evidence");
        }
    }

    private static void ClassifyRole(UsbDeviceRecord device, string text, string id)
    {
        if (device.Service.Equals("nhi", StringComparison.OrdinalIgnoreCase))
        {
            SetClassification(device, "Hub", "High", "Thunderbolt host controller service=nhi");
            return;
        }
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

        if (DeviceMarkerText.ContainsWord(text, "HUB")
            || ContainsAny(device.CompatibleIds, @"USB\CLASS_09")
            || device.Service.Equals("usbhub", StringComparison.OrdinalIgnoreCase)
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

        if (ContainsAny(text, "INTEGRATED", "BUILT-IN", "BUILT IN", "INTERNAL CAMERA")
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
        if (BluetoothEnumeratorId.IsPairedDeviceRecord(device.DeviceInstanceId))
        {
            device.VisualCategory = "BluetoothDevice";
        }
        else if (device.DeviceType.Equals("DeviceInterface", StringComparison.OrdinalIgnoreCase)
                 && device.VisualCategory == "SupportArtifact")
        {
            device.VisualCategory = "HistoricalResidual";
        }

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
        else if (device.Classification == "BuiltIn" && device.Transport is "Internal NVMe" or "Internal Disk")
        {
            device.VisualCategory = "RelatedStorage";
            device.UserMeaning = device.Transport == "Internal NVMe"
                ? "Внутренний NVMe-диск. Это не USB-устройство и не участвует в USB forensic-аудите как внешний носитель."
                : "Внутренний SATA/SCSI-диск. Это не USB-устройство и не участвует в USB forensic-аудите как внешний носитель.";
        }
        else if (device.Classification == "BuiltIn")
        {
            device.UserMeaning = "Встроенное устройство внутренней USB-шины; сохранено в текущей области аудита и явно помечено.";
        }
        else if (device.Transport == "UASP/SCSI")
        {
            device.UserMeaning = "SCSI/UASP storage-запись включена только при наличии removable/external/UASP/topology evidence.";
        }

        if (IsReportable(device)
            && device.VisualCategory == "RelatedStorage"
            && device.Transport is not "Internal NVMe" and not "Internal Disk")
        {
            device.VisualCategory = "RealUsb";
        }

        device.DeviceKind = DeviceKindResolver.Resolve(device);
    }

    private static string EvidenceText(UsbDeviceRecord device) => Join(
        device.DeviceInstanceId, device.Source, device.DeviceType, device.Service,
        device.HardwareIds, device.CompatibleIds, device.LocationInformation, device.LocationPaths,
        device.FriendlyName, device.Manufacturer, device.Product, device.RawJson);

    /// <summary>
    /// Роль устройства нельзя определять по его месту в топологии. Windows пишет
    /// каждому устройству LocationInformation вида "Port_#0008.Hub_#0001" — это
    /// порт и концентратор, в которые устройство воткнуто, а не само устройство.
    /// Пока эта строка попадала в текст признаков, любая флешка и любой телефон
    /// получали роль Hub, уходили в инфраструктуру шины и пропадали из счётчика
    /// физических устройств.
    /// </summary>
    private static string RoleEvidenceText(UsbDeviceRecord device) => PortLocationRegex().Replace(
        Join(device.DeviceInstanceId, device.Source, device.DeviceType, device.Service,
            device.HardwareIds, device.CompatibleIds,
            device.FriendlyName, device.Manufacturer, device.Product, device.RawJson),
        " ");

    [GeneratedRegex(@"Port_#\d+\.Hub_#\d+", RegexOptions.IgnoreCase)]
    private static partial Regex PortLocationRegex();

    private static bool IsSameTopology(UsbDeviceRecord left, UsbDeviceRecord right)
    {
        if (DeviceLiveMatcher.PnpIdsMatch(left.ParentDeviceInstanceId, right.DeviceInstanceId)) { return true; }
        if (DeviceRemovalPolicy.SameContainer(left.ContainerId, right.ContainerId))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(left.ParentIdPrefix)
            && (right.ParentIdPrefix.Contains(left.ParentIdPrefix, StringComparison.OrdinalIgnoreCase)
                || right.Serial.Contains(left.ParentIdPrefix, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        // A historical port path can be reused by unrelated devices.
        return false;
    }

    private static string Join(params string?[] values) =>
        string.Join(" ", values.Where(x => !string.IsNullOrWhiteSpace(x)));

    private static bool ScsiHasExternalBusEvidence(string text, string id) =>
        ContainsUaspMarker(text)
        || ContainsAny(text, "REMOVABLE", "EXTERNAL", "THUNDERBOLT", "USB4")
        || ContainsAny(id, @"VEN_USB", "USBSTOR")
        || ContainsAny(text, "USBROOT", "USB(");

    private static bool ContainsUaspMarker(string value) =>
        value.Contains("UASPSTOR", StringComparison.OrdinalIgnoreCase)
        || value.Contains("UASSTOR", StringComparison.OrdinalIgnoreCase)
        || value.Contains("USB ATTACHED SCSI", StringComparison.OrdinalIgnoreCase)
        || value.Contains(@"USB\CLASS_UAS", StringComparison.OrdinalIgnoreCase);

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
