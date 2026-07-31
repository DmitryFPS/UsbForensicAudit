namespace UsbForensicAudit;

/// <summary>
/// Один способ посчитать устройства для всех отчётов. Раньше каждый отчёт
/// считал по-своему: где-то выводилось число записей реестра, где-то —
/// «реальных USB», где-то — число сведённых устройств. Три разных числа на
/// одном и том же наборе данных заставляют читателя гадать, сколько же
/// носителей на самом деле подключали.
///
/// Главное число здесь одно — сколько физических устройств удалось выделить.
/// Остальные величины подчинённые и объясняют, из чего это число сложилось.
/// </summary>
public sealed record DeviceCountSummary(
    int PhysicalDevices,
    int RegistryRecords,
    int MergedRecords,
    int InfrastructureRecords,
    int RegistryTraceRecords)
{
    public static DeviceCountSummary Empty { get; } = new(0, 0, 0, 0, 0);

    /// <summary>
    /// Считает по записям, отобранным в область USB-аудита. Физическим
    /// устройством считается группа записей с общим сведённым идентификатором:
    /// одна флешка обычно оставляет след и в USBSTOR, и в USB, и в WPD.
    /// </summary>
    public static DeviceCountSummary FromDevices(IEnumerable<UsbDeviceRecord> devices)
    {
        var records = devices as IReadOnlyList<UsbDeviceRecord> ?? devices.ToArray();
        var real = records
            .Where(x => !IsInfrastructure(x) && !IsRegistryTrace(x))
            .ToArray();

        var physical = real
            .Select(GroupKey)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        return new DeviceCountSummary(
            PhysicalDevices: physical,
            RegistryRecords: records.Count,
            MergedRecords: Math.Max(0, real.Length - physical),
            InfrastructureRecords: records.Count(IsInfrastructure),
            RegistryTraceRecords: records.Count(IsRegistryTrace));
    }

    /// <summary>
    /// Одна фраза, которую можно вставить в любой отчёт, не пересчитывая
    /// ничего заново.
    /// </summary>
    public string Describe()
    {
        if (PhysicalDevices == 0)
        {
            return RegistryRecords == 0
                ? "Устройств не обнаружено."
                : $"Физических устройств выделить не удалось; в реестре найдено записей: {RegistryRecords}.";
        }

        var text = $"Физических устройств: {PhysicalDevices}. "
                   + $"Записей в источниках: {RegistryRecords}";
        if (MergedRecords > 0)
        {
            text += $", из них {MergedRecords} сведены к уже перечисленным устройствам "
                    + "(одно устройство оставляет след сразу в нескольких разделах)";
        }

        text += ".";

        if (InfrastructureRecords > 0)
        {
            text += $" Ещё {InfrastructureRecords} записей относятся к самой шине "
                    + "(разветвители, контроллеры, интерфейсы составных устройств) и в это число не входят.";
        }

        if (RegistryTraceRecords > 0)
        {
            text += $" И {RegistryTraceRecords} записей — остаточные следы в реестре без самого устройства.";
        }

        return text;
    }

    private static bool IsInfrastructure(UsbDeviceRecord device) =>
        device.DeviceKind == DeviceKindResolver.Infrastructure
        || device.Classification is "Hub" or "Composite";

    private static bool IsRegistryTrace(UsbDeviceRecord device) =>
        device.DeviceKind == DeviceKindResolver.RegistryTrace
        || device.VisualCategory.Equals("UsbFlagsTrace", StringComparison.OrdinalIgnoreCase);

    private static string GroupKey(UsbDeviceRecord device) =>
        !string.IsNullOrWhiteSpace(device.CanonicalDeviceId)
            ? device.CanonicalDeviceId
            : !string.IsNullOrWhiteSpace(device.DeviceInstanceId)
                ? device.DeviceInstanceId
                : device.DisplayName;
}
