using System.Linq;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Модель «досье устройства» — единственный источник набора полей для HTML- и
/// PDF-отчётов. Тесты фиксируют состав и порядок полей: их изменение должно
/// быть осознанным, потому что меняет оба отчёта сразу.
/// </summary>
public sealed class DeviceCardModelTests
{
    private static UsbDeviceRecord CreateDevice() => new()
    {
        DeviceInstanceId = @"USB\VID_0951&PID_1666\001A92053B6A"
    };

    [Fact]
    public void FieldsOf_returns_full_dossier_in_display_order()
    {
        var fields = DeviceCardModel.FieldsOf(CreateDevice());

        Assert.Equal(26, fields.Count);
        Assert.Equal("Тип", fields[0].Label);
        Assert.Equal("Системный ID", fields[^1].Label);
        Assert.Contains(fields, f => f.Label == "VID/PID");
        Assert.Contains(fields, f => f.Label == "Серийный номер");
    }

    [Fact]
    public void CompactFieldsOf_returns_pdf_subset_in_same_order()
    {
        var compact = DeviceCardModel.CompactFieldsOf(CreateDevice());

        Assert.Equal(16, compact.Count);
        Assert.Equal("Назначение", compact[0].Key);
        Assert.Equal("Системный ID", compact[^1].Key);

        // Тип и источник записи PDF показывает в шапке карточки, не в сетке.
        Assert.DoesNotContain(compact, pair => pair.Key == "Тип");
        Assert.DoesNotContain(compact, pair => pair.Key == "Источник записи");

        // Подмножество сохраняет порядок полного списка.
        var full = DeviceCardModel.FieldsOf(CreateDevice()).Select(f => f.Label).ToList();
        var positions = compact.Select(pair => full.IndexOf(pair.Key)).ToList();
        Assert.Equal(positions.OrderBy(i => i), positions);
    }

    [Fact]
    public void EvidenceRow_matches_evidence_columns()
    {
        var evidence = new EvidenceRecord
        {
            Source = "Реестр",
            EventId = "TEST-1"
        };

        var row = DeviceCardModel.EvidenceRowOf(evidence);

        Assert.Equal(DeviceCardModel.EvidenceColumns.Count, row.Length);
        Assert.Equal("Дата и время", DeviceCardModel.EvidenceColumns[0].Header);
        Assert.Equal("TEST-1", row[4]);
        Assert.Contains("/", row[3]);
    }
}
