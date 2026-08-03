using System.Security.Cryptography;
using System.Text;

namespace UsbForensicAudit;

/// <summary>
/// Заметки эксперта к находкам очистки. Ключ находки строится из её стабильных
/// полей (момент события, область, тип действия, формулировка), поэтому заметка
/// «переживает» повторные сканирования: те же следы получают тот же ключ.
/// Заметки — рабочие пометки эксперта, они хранятся отдельной таблицей и не
/// входят в hash-chain доказательств: аннотация по замыслу изменяема.
/// </summary>
public static class ExpertNotes
{
    /// <summary>Стабильный ключ находки для хранения заметки.</summary>
    public static string KeyOf(CleanupFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var material = $"{finding.TimestampUtc:O}|{finding.Area}|{finding.ActionKind}|{finding.Finding}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)))[..32];
    }

    /// <summary>Проставляет сохранённые заметки на находки результата по ключу.</summary>
    public static void Apply(IEnumerable<CleanupFinding> findings, IReadOnlyDictionary<string, string> notes)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(notes);

        if (notes.Count == 0)
        {
            return;
        }

        foreach (var finding in findings)
        {
            if (notes.TryGetValue(KeyOf(finding), out var note))
            {
                finding.ExpertNote = note;
            }
        }
    }
}
