using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class Stage4TransportClassificationTests
{
    [Fact]
    public void Usbstor_is_mass_storage_over_usb()
    {
        var device = Device(@"USBSTOR\Disk&Ven_Test&Prod_Flash\SERIAL");

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("MSC/USBSTOR", device.Transport);
        Assert.Equal("USB", device.Connection);
        Assert.Equal("External", device.Classification);
        Assert.True(DeviceTransportClassifier.IsReportable(device));
    }

    [Fact]
    public void Uaspstor_service_is_high_confidence_external_uasp()
    {
        var device = Device(@"SCSI\Disk&Ven_Test&Prod_UASP\7&123&0&000000");
        device.Service = "uaspstor";

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("UASP/SCSI", device.Transport);
        Assert.Equal("High", device.TransportConfidence);
        Assert.Equal("External", device.Classification);
        Assert.Contains("Service=uaspstor", device.TransportProvenance);
    }

    [Fact]
    public void Orphan_scsi_with_external_uasp_evidence_is_reportable()
    {
        var device = Device(@"SCSI\Disk&Ven_Test&Prod_Bridge\7&456&0&000000");
        device.HardwareIds = @"SCSI\DiskTest; USB Attached SCSI UAS";
        device.LocationPaths = "PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(4)";

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("UASP/SCSI", device.Transport);
        Assert.Equal("External", device.Classification);
        Assert.True(DeviceTransportClassifier.IsReportable(device));
    }

    [Fact]
    public void Scsi_topology_linked_to_usb_bridge_is_external_candidate()
    {
        var container = "{407B1632-D16B-4F15-9412-29445C59E92A}";
        var bridge = Device(@"USB\VID_152D&PID_0562\BRIDGE01");
        bridge.ContainerId = container;
        var scsi = Device(@"SCSI\Disk&Ven_JMicron&Prod_Generic\7&456&0&000000");
        scsi.ContainerId = container;

        DeviceTransportClassifier.ClassifyAll([bridge, scsi]);

        Assert.Equal("UASP/SCSI", scsi.Transport);
        Assert.Equal("USB", scsi.Connection);
        Assert.Equal("External", scsi.Classification);
        Assert.Contains(scsi.TransportProvenance, x => x.Contains("USB bridge", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Internal_nvme_without_external_topology_is_excluded()
    {
        var device = Device(@"SCSI\Disk&Ven_NVMe&Prod_Internal\4&111&0&000000");
        device.Product = "Internal NVMe SSD";
        device.Service = "stornvme";
        device.LocationPaths = "PCIROOT(0)#PCI(0100)";

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("Unknown", device.Connection);
        Assert.NotEqual("External", device.Classification);
        Assert.False(DeviceTransportClassifier.IsReportable(device));
        Assert.False(DeviceTransportClassifier.IsRelevantLiveCandidate(
            device.DeviceInstanceId, device.Service, locationPaths: device.LocationPaths, name: device.Product));
    }

    [Fact]
    public void Nvme_in_usb4_thunderbolt_tunnel_is_included()
    {
        var device = Device(@"PCI\VEN_8086&DEV_15EF\NVME-ENCLOSURE");
        device.Product = "NVMe enclosure";
        device.Service = "stornvme";
        device.CompatibleIds = "THUNDERBOLT\\External_NVM_Express";
        device.LocationPaths = "PCIROOT(0)#PCI(0700)#USB4(1)";

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("PCIe-tunneled candidate", device.Connection);
        Assert.Equal("External", device.Classification);
        Assert.True(DeviceTransportClassifier.IsReportable(device));
    }

    [Fact]
    public void Live_mtp_candidate_is_detected_and_classified()
    {
        const string id = @"SWD\WPDBUSENUM\{A1B2C3}#0000000000000000";

        Assert.True(DeviceTransportClassifier.IsRelevantLiveCandidate(id, name: "MTP USB Device"));
        var device = Device(id);
        DeviceTransportClassifier.Classify(device);

        Assert.Equal("MTP/PTP/WPD", device.Transport);
        Assert.Equal("External", device.Classification);
    }

    [Fact]
    public void Usb_hub_is_infrastructure()
    {
        var device = Device(@"USB\ROOT_HUB30\4&123&0&0");
        device.Service = "USBHUB3";
        device.FriendlyName = "USB Root Hub (USB 3.0)";

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("Hub", device.Classification);
        Assert.Contains("infrastructure", device.ClassificationProvenance.Single(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Built_in_webcam_remains_in_usb_scope_but_is_marked()
    {
        var device = Device(@"USB\VID_0BDA&PID_58F4\CAMERA01");
        device.FriendlyName = "Integrated Webcam";

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("BuiltIn", device.Classification);
        Assert.True(DeviceTransportClassifier.IsReportable(device));
    }

    [Fact]
    public void Composite_interface_is_marked_separately()
    {
        var device = Device(@"USB\VID_18D1&PID_4EE7&MI_01\PHONE123");

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("Composite", device.Classification);
    }

    [Fact]
    public void Composite_interface_with_generated_id_groups_under_parent()
    {
        var parent = Device(@"USB\VID_18D1&PID_4EE7\5&ABCDEF&0&1");
        parent.Serial = "5&ABCDEF&0&1";
        var child = Device(@"USB\VID_18D1&PID_4EE7&MI_01\5&ABCDEF&0&1");
        child.Serial = "5&ABCDEF&0&1";

        DeviceIdentityGraph.Process([parent, child]);

        Assert.Equal(parent.CanonicalDeviceId, child.CanonicalDeviceId);
    }

    [Theory]
    [InlineData(@"USB\VID_0E0F&PID_0002\VMWARE", "VMware Virtual USB Hub")]
    [InlineData(@"VMBUS\{ABC}\1", "Hyper-V Virtual USB")]
    public void Hypervisor_usb_markers_are_virtual(string id, string name)
    {
        var device = Device(id);
        device.FriendlyName = name;

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("Virtual", device.Classification);
    }

    [Theory]
    [InlineData("Usb4HostRouter")]
    [InlineData("Usb4DeviceRouter")]
    [InlineData("Usb4P2PNetAdapter")]
    public void Official_usb4_router_services_are_recognized(string service)
    {
        var device = Device(@"USB4\ROOT_DEVICE_ROUTER\1");
        device.Service = service;

        DeviceTransportClassifier.Classify(device);

        Assert.Equal("USB4/Thunderbolt", device.Connection);
        Assert.Equal("Hub", device.Classification);
        Assert.True(DeviceTransportClassifier.IsRelevantLiveCandidate(device.DeviceInstanceId, service));
    }

    [Fact]
    public void Unrelated_pci_instance_is_not_a_live_candidate()
    {
        Assert.False(DeviceTransportClassifier.IsRelevantLiveCandidate(
            @"PCI\VEN_10DE&DEV_2684\1", "nvlddmkm", name: "Display adapter"));
    }

    private static UsbDeviceRecord Device(string id) => new()
    {
        Source = "Test",
        VisualCategory = id.StartsWith(@"SCSI\", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith(@"PCI\", StringComparison.OrdinalIgnoreCase)
            ? "RelatedStorage"
            : "RealUsb",
        DeviceInstanceId = id,
        DeviceType = "Test"
    };
}
