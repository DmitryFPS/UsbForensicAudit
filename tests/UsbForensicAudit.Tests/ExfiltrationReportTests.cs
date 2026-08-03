using System;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// HTML-отчёт содержит секцию «Вынос данных» и перечисляет вынесенные файлы.
/// </summary>
public sealed class ExfiltrationReportTests
{
    private static AuditResult ResultWithOutboundFile()
    {
        var result = new AuditResult
        {
            StartedAtUtc = DateTimeOffset.Parse("2026-01-01T10:00:00Z"),
            FinishedAtUtc = DateTimeOffset.Parse("2026-01-01T10:05:00Z")
        };
        var device = new UsbDeviceRecord
        {
            CanonicalDeviceId = "canon-1",
            DeviceInstanceId = @"USB\VID_0951&PID_1666\SN1"
        };
        device.CopyIndications.Add(new CopyIndication
        {
            FileName = "секрет.docx",
            Direction = CopyDirection.ToDevice,
            Confidence = "High",
            Basis = "Журнал изменений NTFS",
            SeenOnDeviceUtc = DateTimeOffset.Parse("2026-01-01T09:50:00Z")
        });
        result.Devices.Add(device);
        result.FileChangeJournals.Add(new FileChangeJournalState { Volume = @"C:\" });
        return result;
    }

    [Fact]
    public void Html_report_includes_exfiltration_section_and_file()
    {
        var html = ForensicReportBuilder.BuildHtml(ResultWithOutboundFile());

        Assert.Contains("id=\"exfiltration\"", html, StringComparison.Ordinal);
        Assert.Contains("Вынос данных на съёмные носители", html, StringComparison.Ordinal);
        Assert.Contains("секрет.docx", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_report_states_when_no_exfiltration()
    {
        var result = new AuditResult
        {
            StartedAtUtc = DateTimeOffset.Parse("2026-01-01T10:00:00Z"),
            FinishedAtUtc = DateTimeOffset.Parse("2026-01-01T10:05:00Z")
        };

        var html = ForensicReportBuilder.BuildHtml(result);

        Assert.Contains("Признаков выноса файлов на съёмные носители не обнаружено", html, StringComparison.Ordinal);
    }
}
