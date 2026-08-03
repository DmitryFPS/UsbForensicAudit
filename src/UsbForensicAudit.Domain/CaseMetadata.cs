namespace UsbForensicAudit;

/// <summary>
/// Карточка дела для цепочки владения (chain of custody): номер дела,
/// кто проводит экспертизу, объект и комментарий. Попадает в шапку отчётов и в
/// манифест пакета доказательств. Пустая карточка означает, что дело не оформлено.
/// </summary>
public sealed class CaseMetadata
{
    public string? CaseNumber { get; init; }
    public string? Examiner { get; init; }
    public string? Subject { get; init; }
    public string? Comment { get; init; }

    public bool IsEmpty =>
        string.IsNullOrWhiteSpace(CaseNumber)
        && string.IsNullOrWhiteSpace(Examiner)
        && string.IsNullOrWhiteSpace(Subject)
        && string.IsNullOrWhiteSpace(Comment);

    public static CaseMetadata None { get; } = new();

    /// <summary>Пары «подпись — значение» только для заполненных полей — для шапки отчёта.</summary>
    public IReadOnlyList<(string Label, string Value)> DisplayFields()
    {
        var fields = new List<(string, string)>();
        Add(fields, "Дело №", CaseNumber);
        Add(fields, "Эксперт", Examiner);
        Add(fields, "Объект", Subject);
        Add(fields, "Комментарий", Comment);
        return fields;
    }

    private static void Add(List<(string, string)> fields, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            fields.Add((label, value.Trim()));
        }
    }
}
