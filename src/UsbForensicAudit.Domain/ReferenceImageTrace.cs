namespace UsbForensicAudit;

/// <summary>
/// Признаки того, что систему развернули из готового образа, а не установили
/// на этой машине с нуля. Это важно для выводов о людях: устройства, попавшие
/// в реестр при подготовке образа, не имеют отношения к тому, кто работает за
/// машиной сейчас. Без такой проверки виртуальные диски сборщика образа и его
/// флешки выглядят в отчёте как чужие подключения к рабочему компьютеру.
/// </summary>
public sealed class ReferenceImageTrace
{
    public List<ImageSignal> Signals { get; } = [];

    /// <summary>
    /// Момент подготовки образа: самая ранняя отметка клонирования. Всё, что в
    /// реестре старше её, пришло из образа.
    /// </summary>
    public DateTimeOffset? PreparedAtUtc { get; set; }

    public DateTimeOffset? DeployedAtUtc { get; set; }

    public bool WasDeployedFromImage => Signals.Any(x => x.IsDecisive);

    public void Add(string title, string detail, bool isDecisive) =>
        Signals.Add(new ImageSignal(title, detail, isDecisive));

    /// <summary>
    /// Пришла ли запись из образа. Отметка клонирования — граница: устройство,
    /// известное системе раньше подготовки образа, видел сборщик образа.
    /// </summary>
    public bool PredatesDeployment(DateTimeOffset? momentUtc) =>
        momentUtc.HasValue && PreparedAtUtc.HasValue && momentUtc.Value < PreparedAtUtc.Value;

    public string Describe()
    {
        if (Signals.Count == 0)
        {
            return "Следов развёртывания из готового образа не найдено: судя по реестру, "
                   + "Windows устанавливали на этой машине.";
        }

        var text = WasDeployedFromImage
            ? "Система развёрнута из готового образа, а не установлена на этой машине с нуля. "
            : "Есть косвенные признаки того, что система могла быть развёрнута из готового образа. ";

        if (PreparedAtUtc.HasValue)
        {
            text += $"Образ подготовлен {DateDisplay.FormatMoscow(PreparedAtUtc)}. "
                    + "Устройства, известные системе раньше этого момента, видел сборщик образа, "
                    + "а не тот, кто работает за машиной сейчас. ";
        }

        text += "Основания: " + string.Join("; ", Signals.Select(x => x.Title.ToLowerInvariant())) + ".";
        return text;
    }
}

public sealed record ImageSignal(string Title, string Detail, bool IsDecisive);
