namespace UsbForensicAudit;

/// <summary>
/// Часть имён Windows даёт устройству по его классу, а не по модели: «USB
/// Composite Device», «USB-устройство ввода». Такое имя ничего не говорит о
/// самой вещи, а модель при этом часто записана рядом — у функции того же
/// устройства. У встроенной камеры ноутбука родительская запись называется
/// «USB Composite Device», а её же функция — «Integrated Camera».
/// </summary>
public static class DeviceNameQuality
{
    private static readonly string[] ClassNames =
    [
        "USB Composite Device",
        "Составное USB устройство",
        "USB Input Device",
        "USB-устройство ввода",
        "HID-совместимое устройство",
        "WinUsb Device",
        "USB Mass Storage Device",
        "Запоминающее устройство для USB",
        "Generic USB Hub",
        "USB Root Hub",
        "Корневой USB-концентратор",
        "Bluetooth Device",
        "Периферийное устройство Bluetooth",
        "Disk drive",
        "Дисковое устройство",
        "USB Video Device",
        "Универсальный компонент программного обеспечения"
    ];

    /// <summary>Имя дано по классу устройства и о модели не говорит ничего.</summary>
    public static bool IsClassName(string? name)
    {
        var text = (name ?? "").Trim();
        if (text.Length == 0)
        {
            return true;
        }

        return ClassNames.Any(x => text.Equals(x, StringComparison.OrdinalIgnoreCase))
               || LooksLikeIdentifier(text);
    }

    /// <summary>
    /// Имени нет вовсе, и вместо него показан идентификатор из реестра.
    /// </summary>
    private static bool LooksLikeIdentifier(string text) =>
        text.Contains('\\')
        && (text.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith(@"BTHENUM\", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith(@"SWD\", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith(@"PCI\", StringComparison.OrdinalIgnoreCase));
}
