namespace UsbForensicAudit;

/// <summary>
/// Цвет строки во вкладке «USB устройства». Раньше цвет показывал раздел реестра,
/// из которого пришла запись, и корневой концентратор материнской платы был
/// такого же зелёного цвета, что и принесённая флешка. Теперь цветом отделено
/// то, что приносили с собой, от того, что всегда было внутри машины.
/// </summary>
public static class DeviceExternalityPalette
{
    private static readonly Dictionary<string, DeviceCategoryColors> Palette =
        new(StringComparer.OrdinalIgnoreCase)
        {
            [DeviceExternality.ExternalMedia] = new("#0E5138", "#EAFFF4"),
            [DeviceExternality.ExternalPeripheral] = new("#14415C", "#DFF3FF"),
            [DeviceExternality.PossiblyExternal] = new("#4A3B12", "#FBEFCF"),
            [DeviceExternality.BuiltInDevice] = new("#1B2C3F", "#9FB4C8"),
            [DeviceExternality.BusInfrastructure] = new("#152234", "#8FA3B7"),
            [DeviceExternality.VirtualDevice] = new("#2C2550", "#C8C0F0"),
            [DeviceExternality.RegistryTrace] = new("#33223A", "#DCC4E6"),
            [DeviceExternality.Undetermined] = new("#3A2A1E", "#F5DCC8")
        };

    public static IReadOnlyCollection<string> KnownGroups => Palette.Keys;

    public static DeviceCategoryColors For(string? externality) =>
        !string.IsNullOrWhiteSpace(externality) && Palette.TryGetValue(externality, out var colors)
            ? colors
            : Palette[DeviceExternality.Undetermined];

    public static bool IsKnown(string? externality) =>
        !string.IsNullOrWhiteSpace(externality) && Palette.ContainsKey(externality);
}

/// <summary>
/// Цвета в том виде, в каком их понимает разметка окна.
/// </summary>
public sealed record DeviceCategoryColors(string Background, string Foreground);
