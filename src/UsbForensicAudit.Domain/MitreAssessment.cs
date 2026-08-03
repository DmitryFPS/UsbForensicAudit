namespace UsbForensicAudit;

/// <summary>
/// Техника MITRE ATT&amp;CK: идентификатор, название, тактика и ссылка. Каталог
/// ограничен техниками, релевантными USB-форензике, чтобы отчёт говорил на языке
/// SOC/IR без ручного перевода находок аналитиком.
/// </summary>
public sealed class MitreTechnique
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Tactic { get; init; }
    public string Url => $"https://attack.mitre.org/techniques/{Id.Replace('.', '/')}/";

    public static readonly MitreTechnique RemovableMediaReplication = new()
    {
        Id = "T1091",
        Name = "Распространение через съёмные носители",
        Tactic = "Первоначальный доступ / Боковое перемещение"
    };

    public static readonly MitreTechnique ExfiltrationOverUsb = new()
    {
        Id = "T1052.001",
        Name = "Вынос данных на физический носитель (USB)",
        Tactic = "Эксфильтрация"
    };

    public static readonly MitreTechnique IndicatorRemoval = new()
    {
        Id = "T1070",
        Name = "Удаление следов",
        Tactic = "Обход защиты"
    };

    public static readonly MitreTechnique ClearWindowsEventLogs = new()
    {
        Id = "T1070.001",
        Name = "Очистка журналов событий Windows",
        Tactic = "Обход защиты"
    };
}

/// <summary>Техника, для которой в аудите нашлись основания, с обоснованием и числом опор.</summary>
public sealed class MitreFinding
{
    public required MitreTechnique Technique { get; init; }
    public required string Rationale { get; init; }
    public required int EvidenceCount { get; init; }
}

/// <summary>
/// Сопоставление находок аудита с техниками MITRE ATT&amp;CK. Только техники,
/// подкреплённые данными: пустой список означает «сопоставимых техник не найдено»,
/// а не «ничего не проверяли».
/// </summary>
public sealed class MitreAssessment
{
    public required IReadOnlyList<MitreFinding> Findings { get; init; }

    public bool HasFindings => Findings.Count > 0;

    public string Verdict()
    {
        if (!HasFindings)
        {
            return "Сопоставимых с MITRE ATT&CK техник по собранным данным не выявлено.";
        }

        var ids = string.Join(", ", Findings.Select(x => x.Technique.Id));
        return $"Сопоставлено техник MITRE ATT&CK: {Findings.Count} ({ids}). "
               + "Сопоставление основано на косвенных следах и требует проверки аналитиком.";
    }

    public static MitreAssessment Empty { get; } = new() { Findings = [] };
}
