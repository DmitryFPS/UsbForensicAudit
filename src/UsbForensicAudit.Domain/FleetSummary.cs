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

    /// <summary>
    /// Сопоставление по серийному номеру (точное — это тот же физический
    /// экземпляр). Если false — сопоставление по VID:PID, то есть по МОДЕЛИ:
    /// «несколько машин» может означать несколько одинаковых устройств, а не
    /// перемещение одного. Это различие критично для вывода следователя.
    /// </summary>
    public required bool IdentifiedBySerial { get; init; }

    public string FirstSeenText => DateDisplay.FormatMoscowOr(FirstSeenUtc, "неизвестно");
    public string LastSeenText => DateDisplay.FormatMoscowOr(LastSeenUtc, "неизвестно");
    public string MachinesText => string.Join(", ", Machines);

    /// <summary>Как читать кросс-машинность: точный экземпляр или совпадение модели.</summary>
    public string MatchBasisText => IdentifiedBySerial
        ? "по серийному номеру — тот же экземпляр"
        : "по VID:PID — возможно, разные устройства одной модели";
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

        var bySerial = CrossMachineDevices.Count(x => x.IdentifiedBySerial);
        var byModel = CrossMachineDevices.Count - bySerial;
        var tail = bySerial > 0
            ? $"Из них по серийному номеру (тот же экземпляр на разных ПК): {bySerial} — это сильный сигнал переноса данных."
            : "Все совпадения — по модели (VID:PID), а не по серийнику: это могут быть разные одинаковые устройства, нужна ручная проверка.";
        return $"Обработано машин: {MachineCount}. "
               + $"Устройств, засветившихся на нескольких машинах: {CrossMachineDevices.Count}"
               + (byModel > 0 ? $" (по модели: {byModel})" : "") + ". " + tail;
    }

    public static FleetSummary Empty { get; } = new() { Devices = [], MachineCount = 0 };
}
