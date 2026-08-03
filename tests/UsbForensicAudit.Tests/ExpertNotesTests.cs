using System;
using System.Collections.Generic;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Заметки эксперта: стабильность ключа находки между сканированиями,
/// возврат заметок на находки и попадание заметки в текст для отчётов.
/// </summary>
public sealed class ExpertNotesTests
{
    private static CleanupFinding Finding(string finding = "Удалён ключ реестра", string area = "Registry") => new()
    {
        TimestampUtc = new DateTimeOffset(2026, 5, 1, 10, 0, 0, TimeSpan.Zero),
        Area = area,
        ActionKind = "Deletion",
        Finding = finding,
        Details = "USBSTOR очищен"
    };

    [Fact]
    public void Key_is_stable_for_same_finding_across_scans()
    {
        Assert.Equal(ExpertNotes.KeyOf(Finding()), ExpertNotes.KeyOf(Finding()));
    }

    [Fact]
    public void Key_differs_for_different_findings()
    {
        Assert.NotEqual(ExpertNotes.KeyOf(Finding()), ExpertNotes.KeyOf(Finding(finding: "Другая находка")));
        Assert.NotEqual(ExpertNotes.KeyOf(Finding()), ExpertNotes.KeyOf(Finding(area: "EventLog")));
    }

    [Fact]
    public void Apply_restores_note_by_key()
    {
        var finding = Finding();
        var notes = new Dictionary<string, string> { [ExpertNotes.KeyOf(finding)] = "Проверено: чистил админ по заявке." };

        ExpertNotes.Apply([finding, Finding(finding: "Без заметки")], notes);

        Assert.Equal("Проверено: чистил админ по заявке.", finding.ExpertNote);
    }

    [Fact]
    public void Details_with_note_appends_note_for_reports()
    {
        var finding = Finding();
        Assert.Equal(finding.Details, finding.DetailsWithNote);

        finding.ExpertNote = "Согласуется с журналом заявок.";
        Assert.Contains("USBSTOR очищен", finding.DetailsWithNote);
        Assert.Contains("Заметка эксперта: Согласуется с журналом заявок.", finding.DetailsWithNote);
    }
}
