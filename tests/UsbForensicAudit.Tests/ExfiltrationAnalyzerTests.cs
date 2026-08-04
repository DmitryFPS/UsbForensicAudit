using System;
using System.Linq;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Вердикт «вынос данных наружу»: в вынос попадают файлы, ушедшие с компьютера
/// на съёмный носитель (направление ToDevice). Перенос с неопределённым
/// направлением в вынос не попадает, но показывается отдельным списком
/// (UndirectedFiles) — это подтверждённые по времени совпадения, скрывать
/// которые нельзя, — и упоминается в вердикте.
/// </summary>
public sealed class ExfiltrationAnalyzerTests
{
    private static UsbDeviceRecord DeviceWith(params CopyIndication[] indications)
    {
        var device = new UsbDeviceRecord
        {
            CanonicalDeviceId = "canon-1",
            DeviceInstanceId = @"USB\VID_0951&PID_1666\SN1"
        };
        device.CopyIndications.AddRange(indications);
        return device;
    }

    private static CopyIndication Outbound(string name, string confidence = "High") => new()
    {
        FileName = name,
        Direction = CopyDirection.ToDevice,
        Confidence = confidence,
        Basis = "Журнал изменений NTFS",
        SeenOnDeviceUtc = DateTimeOffset.Parse("2026-01-02T10:00:00Z")
    };

    [Fact]
    public void Outbound_files_are_reported_as_exfiltration()
    {
        var result = new AuditResult();
        result.Devices.Add(DeviceWith(Outbound("secret.docx"), Outbound("plan.xlsx")));
        result.FileChangeJournals.Add(new FileChangeJournalState { Volume = @"C:\" });

        var summary = ExfiltrationAnalyzer.Analyze(result);

        Assert.True(summary.HasFindings);
        Assert.Equal(2, summary.OutboundCount);
        Assert.Equal(2, summary.ConfirmedCount);
        Assert.Equal(1, summary.DeviceCount);
        Assert.Contains("Признаки выноса данных", summary.Verdict());
    }

    [Fact]
    public void Inbound_and_undirected_are_not_counted_as_exfiltration()
    {
        var result = new AuditResult();
        result.Devices.Add(DeviceWith(
            new CopyIndication { FileName = "in.docx", Direction = CopyDirection.ToComputer, Confidence = "High" },
            new CopyIndication { FileName = "maybe.docx", Direction = CopyDirection.Unknown, Confidence = "Low" }));

        var summary = ExfiltrationAnalyzer.Analyze(result);

        Assert.False(summary.HasFindings);
        Assert.Equal(0, summary.OutboundCount);
        Assert.Equal(1, summary.UndirectedCount);
        Assert.Contains("направление не определено", summary.Verdict());
    }

    [Fact]
    public void Undirected_transfers_are_shown_not_hidden()
    {
        // Регрессия: переносы с неопределённым направлением — самые уверенные
        // совпадения (разница < 10 минут) — раньше не показывались вовсе.
        var result = new AuditResult();
        result.Devices.Add(DeviceWith(
            new CopyIndication { FileName = "maybe.docx", Direction = CopyDirection.Unknown, Confidence = "High" }));

        var summary = ExfiltrationAnalyzer.Analyze(result);

        Assert.True(summary.HasAnyIndication);
        Assert.Single(summary.UndirectedFiles);
        Assert.True(summary.UndirectedFiles[0].IsUndirected);
        Assert.Contains("направление не определено", summary.UndirectedFiles[0].DirectionText);
        Assert.Contains(summary.DisplayFiles, x => x.FileName == "maybe.docx");
    }

    [Fact]
    public void Undirected_note_survives_when_outbound_present()
    {
        // Регрессия: при наличии хотя бы одного выноса оговорка о переносах
        // без направления полностью исчезала из вердикта.
        var result = new AuditResult();
        result.Devices.Add(DeviceWith(
            Outbound("secret.docx"),
            new CopyIndication { FileName = "maybe.docx", Direction = CopyDirection.Unknown, Confidence = "High" }));
        result.FileChangeJournals.Add(new FileChangeJournalState { Volume = @"C:\" });

        var summary = ExfiltrationAnalyzer.Analyze(result);

        Assert.True(summary.HasFindings);
        Assert.Equal(1, summary.UndirectedCount);
        Assert.Contains("Признаки выноса данных", summary.Verdict());
        Assert.Contains("направление не определено", summary.Verdict());
    }

    [Fact]
    public void Confirmed_outbound_sorted_before_name_only_matches()
    {
        var result = new AuditResult();
        result.Devices.Add(DeviceWith(
            Outbound("weak.docx", confidence: "Low"),
            Outbound("strong.docx", confidence: "High")));
        result.FileChangeJournals.Add(new FileChangeJournalState { Volume = @"C:\" });

        var summary = ExfiltrationAnalyzer.Analyze(result);

        Assert.Equal("strong.docx", summary.OutboundFiles[0].FileName);
        Assert.True(summary.OutboundFiles[0].IsConfirmed);
        Assert.False(summary.OutboundFiles[1].IsConfirmed);
    }

    [Fact]
    public void No_journal_is_called_out_in_verdict()
    {
        var result = new AuditResult();

        var summary = ExfiltrationAnalyzer.Analyze(result);

        Assert.False(summary.JournalAvailable);
        Assert.Contains("Журнал изменений NTFS не читался", summary.Verdict());
    }
}
