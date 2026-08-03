using System.Text.Json;

namespace UsbForensicAudit;

/// <summary>
/// Разбор карточки дела из JSON. Чистый и тестируемый; файловая обёртка — в
/// инфраструктуре. Пустая или пробельная строка даёт пустую карточку.
/// </summary>
public static class CaseMetadataReader
{
    public const string DefaultFileName = "case.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public static CaseMetadata Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return CaseMetadata.None;
        }

        var dto = JsonSerializer.Deserialize<Dto>(json, JsonOptions) ?? new Dto();
        return new CaseMetadata
        {
            CaseNumber = dto.CaseNumber,
            Examiner = dto.Examiner,
            Subject = dto.Subject,
            Comment = dto.Comment
        };
    }

    private sealed class Dto
    {
        public string? CaseNumber { get; set; }
        public string? Examiner { get; set; }
        public string? Subject { get; set; }
        public string? Comment { get; set; }
    }
}
