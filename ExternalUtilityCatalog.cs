using System.IO;

namespace UsbForensicAudit;

public static class ExternalUtilityCatalog
{
    public static readonly ExternalUtilityDefinition[] Definitions =
    [
        new()
        {
            Id = "usbdetector",
            DisplayName = "USBDetector",
            ProcessNames = ["USBDetector.exe", "USBDetector"],
            Description = "Поиск USB в реестре и раздел «Другие следы подключения устройств»."
        },
        new()
        {
            Id = "usbdeview",
            DisplayName = "USBDeview",
            ProcessNames = ["USBDeview.exe", "USBDeview"],
            Description = "Список подключавшихся USB-устройств (NirSoft)."
        },
        new()
        {
            Id = "usboblivion",
            DisplayName = "USB Oblivion",
            ProcessNames = ["USBOblivion.exe", "USBOblivion64.exe", "USBOblivion"],
            Description = "Утилита удаления следов USB из реестра."
        }
    ];

    public static ExternalUtilityDefinition? MatchProcess(string processName)
    {
        var fileName = Path.GetFileName(processName);
        var baseName = Path.GetFileNameWithoutExtension(fileName);
        return Definitions.FirstOrDefault(def =>
            def.ProcessNames.Any(name =>
            {
                var patternBase = Path.GetFileNameWithoutExtension(name);
                return patternBase.Equals(baseName, StringComparison.OrdinalIgnoreCase)
                       || name.Equals(fileName, StringComparison.OrdinalIgnoreCase)
                       || name.Equals(processName, StringComparison.OrdinalIgnoreCase);
            }));
    }
}
