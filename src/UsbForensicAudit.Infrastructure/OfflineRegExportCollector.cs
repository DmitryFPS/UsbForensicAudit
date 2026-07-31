using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

/// <summary>
/// Разбор реестра, принесённого с другой машины в виде файлов reg export.
/// Раньше программа умела работать только с реестром той машины, на которой
/// запущена, поэтому анализ чужого компьютера приходилось делать вручную.
/// </summary>
public static partial class OfflineRegExportCollector
{
    private static readonly Regex VidPidRegex = VidPid();
    private static readonly Regex EnumKeyRegex = EnumKey();

    /// <summary>
    /// Читает все файлы .reg из папки и строит по ним записи устройств.
    /// </summary>
    public static IReadOnlyList<UsbDeviceRecord> CollectFromDirectory(string directory, List<string> warnings)
    {
        if (!Directory.Exists(directory))
        {
            warnings.Add($"Папка с экспортом реестра не найдена: {directory}");
            return [];
        }

        var keys = new List<RegExportKey>();
        foreach (var file in Directory.EnumerateFiles(directory, "*.reg", SearchOption.AllDirectories).Take(512))
        {
            try
            {
                keys.AddRange(RegExportParser.ParseFile(file));
            }
            catch (Exception ex)
            {
                warnings.Add($"Не удалось разобрать {file}: {ex.Message}");
            }
        }

        if (keys.Count == 0)
        {
            warnings.Add($"В папке {directory} не найдено разбираемых файлов экспорта реестра.");
            return [];
        }

        warnings.Add(
            $"Офлайн-разбор экспорта реестра из {directory}: прочитано разделов — {keys.Count}. "
            + "Время изменения ключей в экспорте не сохраняется, поэтому датировать подключения "
            + "по нему нельзя; доступны только идентификаторы устройств и свойства PnP.");

        return Build(keys);
    }

    public static IReadOnlyList<UsbDeviceRecord> Build(IReadOnlyList<RegExportKey> keys)
    {
        var records = new List<UsbDeviceRecord>();
        foreach (var key in keys)
        {
            var match = EnumKeyRegex.Match(key.Path);
            if (!match.Success)
            {
                continue;
            }

            var bus = match.Groups["bus"].Value;
            var family = match.Groups["family"].Value;
            var instance = match.Groups["instance"].Value;
            if (UsbRegistryCollector.IsServiceSubKey(instance))
            {
                continue;
            }

            var deviceId = $@"{bus}\{family}\{instance}";
            var record = new UsbDeviceRecord
            {
                Source = $"Офлайн-экспорт реестра: {bus}",
                VisualCategory = "HistoricalResidual",
                UserMeaning = "Запись из реестра, принесённого с другой машины. Подтверждает, "
                              + "что устройство было известно системе; время подключения экспорт не сохраняет.",
                DeviceInstanceId = deviceId,
                DeviceType = bus.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase) ? "Накопитель" : bus,
                Serial = instance,
                FriendlyName = key.GetString("FriendlyName"),
                Manufacturer = key.GetString("Mfg"),
                Product = key.GetString("DeviceDesc"),
                ClassGuid = key.GetString("ClassGUID"),
                Service = key.GetString("Service"),
                HardwareIds = key.GetString("HardwareID"),
                CompatibleIds = key.GetString("CompatibleIDs"),
                ContainerId = key.GetString("ContainerID"),
                ParentIdPrefix = key.GetString("ParentIdPrefix"),
                LocationInformation = key.GetString("LocationInformation"),
                LocationPaths = key.GetString("LocationPaths"),
                DateConfidence = "Экспорт реестра не сохраняет время изменения ключей: "
                                 + "дату подключения по этому источнику установить нельзя.",
                RawJson = JsonSerializer.Serialize(new { RegistryPath = key.Path, Offline = true })
            };

            var vidPid = VidPidRegex.Match(family);
            if (vidPid.Success)
            {
                record.Vid = vidPid.Groups[1].Value.ToUpperInvariant();
                record.Pid = vidPid.Groups[2].Value.ToUpperInvariant();
            }

            if (deviceId.Contains("WPDBUSENUM", StringComparison.OrdinalIgnoreCase))
            {
                var identity = UsbRegistryForensicHelpers.ParseWpdIdentity(instance);
                if (!string.IsNullOrWhiteSpace(identity.Serial))
                {
                    record.Serial = identity.Serial;
                }

                if (!string.IsNullOrWhiteSpace(identity.BackingDeviceInstanceId))
                {
                    record.IdentityAliases.Add(identity.BackingDeviceInstanceId);
                }
            }

            records.Add(record);
        }

        DeviceTransportClassifier.ClassifyAll(records);
        DeviceIdentityGraph.Process(records);
        return records;
    }

    [GeneratedRegex(@"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex VidPid();

    [GeneratedRegex(
        @"\\Enum\\(?<bus>USBSTOR|USB4|USB|SCSI|SD|SDBUS|USBSER|BTHENUM|BTHLEDEVICE|SWD\\WPDBUSENUM)\\(?<family>[^\\]+)\\(?<instance>[^\\]+)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EnumKey();
}
