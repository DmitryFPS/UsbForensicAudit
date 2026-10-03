using System.Text.Json;
using Microsoft.Win32;

namespace UsbForensicAudit;

internal static class BluetoothCacheCollector
{
    internal static void Collect(IEnumerable<string> controlSets, List<UsbDeviceRecord> records, List<string> warnings)
    {
        foreach (var controlSet in controlSets)
        {
            var path = $@"SYSTEM\{controlSet}\Services\BTHPORT\Parameters\Devices";
            try
            {
                using var root = Registry.LocalMachine.OpenSubKey(path);
                foreach (var name in root?.GetSubKeyNames() ?? [])
                {
                    var source = $@"HKLM\{path}\{name}";
                    if (BluetoothCacheIdentity.AddressFromPath(source).Length == 0) { continue; }
                    using var key = root!.OpenSubKey(name);
                    if (key is null) { continue; }
                    var display = BluetoothArtifactCollector.ReadBinaryName(key);
                    var cod = key.GetValue("COD") as int?;
                    foreach (var device in records.Where(x => BluetoothEnumeratorId.DeviceAddress(x.DeviceInstanceId)
                                 .Equals(name, StringComparison.OrdinalIgnoreCase)))
                    {
                        device.BluetoothClassOfDevice = cod;
                    }
                    records.Add(new UsbDeviceRecord
                    {
                        DeviceInstanceId = source,
                        DeviceType = "BluetoothCache",
                        Source = "Registry: Bluetooth device cache",
                        FriendlyName = display.Length > 0 ? display : "Bluetooth-устройство " + name,
                        BluetoothClassOfDevice = cod,
                        RegistryLastWriteUtc = RegistryKeyTimestamps.GetLastWriteUtc(key),
                        UserMeaning = "Сохранённая запись Bluetooth. Может оставаться после отмены сопряжения; текущее соединение ею не подтверждается.",
                        RawJson = JsonSerializer.Serialize(new { RegistryPath = source })
                    });
                }
            }
            catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                warnings.Add($"Не удалось полностью прочитать кэш Bluetooth HKLM\\{path}: {ex.Message}");
            }
        }
    }
}
