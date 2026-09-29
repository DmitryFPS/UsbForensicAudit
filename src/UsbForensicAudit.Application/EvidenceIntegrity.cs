namespace UsbForensicAudit;

/// <summary>
/// Порт верификации целостности доказательной базы: hash-chain в
/// evidence.jsonl и печати сессий в audit.sqlite. Содержимое рабочих карточек
/// SQLite и подлинность источников этой проверкой не удостоверяются.
/// </summary>
public interface IEvidenceIntegrityVerifier
{
    public IntegrityReport Verify();
}

/// <summary>Итог проверки целостности доказательной базы.</summary>
public sealed class IntegrityReport
{
    public string VerificationScope => "Проверены цепочка evidence.jsonl и печати сессий. Содержимое рабочих карточек SQLite не сверялось.";
    public bool DatabaseRecordsVerified => false;

    /// <summary>Всего записей в журнале доказательств.</summary>
    public int TotalRecords { get; init; }

    /// <summary>Разрывы hash-chain: подмена, удаление или порча записей.</summary>
    public IReadOnlyList<ChainBreak> ChainBreaks { get; init; } = [];

    /// <summary>Сверка печатей сессий (журнал против базы данных).</summary>
    public IReadOnlyList<SessionSealCheck> SealChecks { get; init; } = [];

    /// <summary>Журнал доказательств отсутствует; при наличии сессий в базе это нарушение.</summary>
    public bool JournalMissing { get; init; }

    /// <summary>Целостность подтверждена: нет ни разрывов цепочки, ни расхождений печатей.</summary>
    public bool IsIntact => !JournalMissing
                            && ChainBreaks.Count == 0
                            && SealChecks.All(check => check.Status != SealStatus.Mismatch);
}

/// <summary>Разрыв hash-chain в журнале доказательств.</summary>
public sealed class ChainBreak
{
    /// <summary>Номер строки журнала (с единицы), где обнаружен разрыв.</summary>
    public int LineNumber { get; init; }

    /// <summary>Человекочитаемое описание причины.</summary>
    public string Reason { get; init; } = "";
}

/// <summary>Сверка печати одной сессии: журнал против audit.sqlite.</summary>
public sealed class SessionSealCheck
{
    public string SessionId { get; init; } = "";

    /// <summary>Итоговый хеш сессии, вычисленный по журналу.</summary>
    public string JournalHash { get; init; } = "";

    /// <summary>Печать, сохранённая в базе данных при записи сессии.</summary>
    public string? StoredSeal { get; init; }

    public SealStatus Status { get; init; }
}

/// <summary>Статус сверки печати сессии.</summary>
public enum SealStatus
{
    /// <summary>Печать совпадает с журналом.</summary>
    Match,

    /// <summary>Печать не совпадает: база или журнал изменены после записи.</summary>
    Mismatch,

    /// <summary>Печати в базе нет (сессия записана до внедрения печатей).</summary>
    NotSealed
}
