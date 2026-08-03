namespace UsbForensicAudit;

/// <summary>
/// Одно устройство в разрезе всего парка машин: где именно оно засветилось.
/// Перемещение одного носителя между несколькими ПК — сильный сигнал утечки,
/// который на отдельной машине не виден.
/// </summary>
public sealed class FleetDevice
{
    public required string IdentityKey { get; init; }
    public required string DisplayName { get; init; }
    public required IReadOnlyList<string> Machines { get; init; }
    public DateTimeOffset? FirstSeenUtc { get; init; }
    public DateTimeOffset? LastSeenUtc { get; init; }

    public int MachineCount => Machines.Count;

    /// <summary>Устройство побывало более чем на одной машине парка.</summary>
    public bool IsCrossMachine => MachineCount > 1;

    public string FirstSeenText => DateDisplay.FormatMoscowOr(FirstSeenUtc, "неизвестно");
    public string LastSeenText => DateDisplay.FormatMoscowOr(LastSeenUtc, "неизвестно");
    public string MachinesText => string.Join(", ", Machines);
}

/// <summary>
/// Сводка по парку машин: какие устройства подключались и какие из них
/// перемещались между машинами. Отвечает на вопрос, недоступный при анализе
/// одной машины, — «одна и та же флешка побывала на разных ПК».
/// </summary>
public sealed class FleetSummary
{
    public required IReadOnlyList<FleetDevice> Devices { get; init; }
    public required int MachineCount { get; init; }

    public IReadOnlyList<FleetDevice> CrossMachineDevices =>
        Devices.Where(x => x.IsCrossMachine).ToArray();

    public bool HasCrossMachineDevices => CrossMachineDevices.Count > 0;

    public string Verdict()
    {
        if (MachineCount == 0)
        {
            return "Нет данных по парку машин для сопоставления.";
        }

        if (!HasCrossMachineDevices)
        {
            return $"Обработано машин: {MachineCount}. Устройств, перемещавшихся между машинами, не обнаружено.";
        }

        return $"Обработано машин: {MachineCount}. "
               + $"Устройств, засветившихся на нескольких машинах: {CrossMachineDevices.Count}. "
               + "Перемещение носителя между ПК стоит проверить — это возможный канал переноса данных.";
    }

    public static FleetSummary Empty { get; } = new() { Devices = [], MachineCount = 0 };
}
