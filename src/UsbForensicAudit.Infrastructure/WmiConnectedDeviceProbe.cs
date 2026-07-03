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
                "SELECT PNPDeviceID FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%' OR PNPDeviceID LIKE 'USBSTOR%'");

            foreach (ManagementObject item in searcher.Get())
            {
                pnpIdentifiers.Add(item["PNPDeviceID"]?.ToString());
            }

            using var diskSearcher = new ManagementObjectSearcher(
                "SELECT PNPDeviceID FROM Win32_DiskDrive WHERE InterfaceType = 'USB'");

            foreach (ManagementObject disk in diskSearcher.Get())
            {
                pnpIdentifiers.Add(disk["PNPDeviceID"]?.ToString());
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
