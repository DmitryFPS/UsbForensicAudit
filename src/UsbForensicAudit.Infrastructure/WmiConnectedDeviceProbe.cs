using System.Management;

namespace UsbForensicAudit;

/// <summary>
/// Инфраструктурная реализация <see cref="IConnectedDeviceProbe"/>: собирает идентификаторы
/// подключённых USB-устройств и буквы съёмных дисков через WMI и строит чистый индекс сопоставления.
/// </summary>
public sealed class WmiConnectedDeviceProbe : IConnectedDeviceProbe
{
    public ConnectedDeviceIndex Capture()
    {
        var pnpIdentifiers = new List<string?>();
        var driveLetters = new List<string?>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT PNPDeviceID, Service, Name FROM Win32_PnPEntity " +
                "WHERE PNPDeviceID LIKE 'USB%' OR PNPDeviceID LIKE 'USBSTOR%' OR PNPDeviceID LIKE 'SCSI%' " +
                "OR PNPDeviceID LIKE 'SWD%' OR PNPDeviceID LIKE 'USB4%' OR PNPDeviceID LIKE 'PCI%' " +
                "OR Service='uaspstor' OR Service='Usb4HostRouter' OR Service='Usb4DeviceRouter' OR Service='Usb4P2PNetAdapter'");

            foreach (ManagementObject item in searcher.Get())
            {
                var pnpId = item["PNPDeviceID"]?.ToString() ?? "";
                var metadata = LiveDeviceMetadataReader.Read(pnpId);
                if (DeviceTransportClassifier.IsRelevantLiveCandidate(
                        pnpId, item["Service"]?.ToString() ?? "", metadata.HardwareIds,
                        metadata.CompatibleIds, metadata.LocationPaths, item["Name"]?.ToString() ?? "")
                    || DeviceTransportClassifier.IsBuiltinStorageLiveCandidate(
                        pnpId, item["Service"]?.ToString() ?? "", metadata.HardwareIds,
                        metadata.CompatibleIds, metadata.LocationPaths, item["Name"]?.ToString() ?? ""))
                {
                    pnpIdentifiers.Add(pnpId);
                }
            }

            using var diskSearcher = new ManagementObjectSearcher(
                "SELECT PNPDeviceID, InterfaceType, MediaType, Model FROM Win32_DiskDrive " +
                "WHERE InterfaceType='USB' OR MediaType='Removable Media' OR MediaType='External hard disk media' OR PNPDeviceID LIKE 'SCSI%'");

            foreach (ManagementObject disk in diskSearcher.Get())
            {
                var pnpId = disk["PNPDeviceID"]?.ToString() ?? "";
                var mediaType = disk["MediaType"]?.ToString() ?? "";
                var metadata = LiveDeviceMetadataReader.Read(pnpId);
                if (DeviceTransportClassifier.IsRelevantLiveCandidate(
                        pnpId, metadata.Service, metadata.HardwareIds, metadata.CompatibleIds,
                        metadata.LocationPaths, disk["Model"]?.ToString() ?? "", mediaType)
                    || DeviceTransportClassifier.IsBuiltinStorageLiveCandidate(
                        pnpId, metadata.Service, metadata.HardwareIds, metadata.CompatibleIds,
                        metadata.LocationPaths, disk["Model"]?.ToString() ?? "", mediaType))
                {
                    pnpIdentifiers.Add(pnpId);
                }
            }

            using var volumeSearcher = new ManagementObjectSearcher(
                "SELECT DeviceID, DriveType FROM Win32_LogicalDisk WHERE DriveType = 2");

            foreach (ManagementObject volume in volumeSearcher.Get())
            {
                driveLetters.Add(volume["DeviceID"]?.ToString());
            }
        }
        catch
        {
            // Если WMI недоступен, обогащение работает только на основе событий.
        }

        return ConnectedDeviceIndex.Build(pnpIdentifiers, driveLetters);
    }
}
