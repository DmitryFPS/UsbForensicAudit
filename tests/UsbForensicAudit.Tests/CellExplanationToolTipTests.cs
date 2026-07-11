using System.Globalization;
using System.Windows;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class CellExplanationToolTipTests
{
    [Fact]
    public void Every_visible_column_has_a_readable_explanation()
    {
        var device = new UsbDeviceRecord
        {
            UserMeaning = "Реальное USB-устройство",
            FriendlyName = "Тестовая флешка",
            VisualCategory = "RealUsb",
            Transport = "UASP/SCSI",
            Connection = "USB",
            Classification = "External",
            ClassificationConfidence = "High",
            ClassificationProvenance = ["removable transport evidence"],
            FirstConnectedUtc = DateTimeOffset.UtcNow,
            LastSeenUtc = DateTimeOffset.UtcNow,
            Vid = "0951",
            Pid = "1666",
            Serial = "SERIAL",
            Source = "Registry: USB",
            DeviceInstanceId = @"USB\VID_0951&PID_1666\SERIAL"
        };
        var evidence = new EvidenceRecord
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            EvidenceCategory = "Подключение USB",
            Source = "EventLog: System",
            EvidenceStrength = "Direct",
            Confidence = "High",
            EventId = "400",
            DeviceHint = device.DeviceInstanceId,
            UserExplanation = "Windows зафиксировала подключение.",
            Summary = "Kernel-PnP event",
            Provenance = "channel=System; record=42"
        };
        var cleanup = new CleanupFinding
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            ActionKind = "ToolLaunch",
            Assessment = "Suspicious",
            InitiatorKind = "User",
            InitiatorAccount = @"PC\Analyst",
            PossibleTool = "USB Oblivion",
            Confidence = "Indirect",
            Severity = "Medium",
            Area = "Cleaner Artifacts",
            Finding = "Обнаружен запуск утилиты",
            Details = "Требуется ручная проверка."
        };

        AssertAllColumns(device,
        [
            "Что это за запись", "Имя устройства", "Тип", "Transport", "Connection",
            "Classification", "Confidence / evidence", "Когда подключали", "Когда отключали",
            "Последняя активность", "Пояснение по датам", "Производитель", "Модель",
            "VID / PID", "Серийный номер", "Расположение в USB",
            "Откуда взята информация", "Системный ID"
        ]);
        AssertAllColumns(evidence,
        [
            "Дата и время", "Что произошло", "Откуда взято", "Сила доказательства",
            "Уверенность", "ID события/записи", "Связанное устройство", "Простыми словами",
            "Подробности", "Provenance"
        ]);
        AssertAllColumns(cleanup,
        [
            "Дата и время", "Тип действия", "Статус", "Инициатор", "Инструмент",
            "Уверенность", "Риск", "Где искали", "Что найдено", "Подробности"
        ]);
    }

    [Theory]
    [InlineData("Direct", "непосредственно")]
    [InlineData("Corroborating", "вместе с другими")]
    [InlineData("Indirect", "не доказывает")]
    public void Evidence_strength_is_explained_without_overstatement(
        string strength,
        string expectedText)
    {
        var record = new EvidenceRecord { EvidenceStrength = strength };

        var explanation = CellExplanationText.Explain(record, "Сила доказательства");

        Assert.NotNull(explanation);
        Assert.Contains(expectedText, explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Technical_device_identifiers_are_explained_in_plain_language()
    {
        var device = new UsbDeviceRecord
        {
            Vid = "0951",
            Pid = "1666",
            DeviceInstanceId = @"USB\VID_0951&PID_1666\SERIAL"
        };

        var vidPid = CellExplanationText.Explain(device, "VID / PID");
        var instanceId = CellExplanationText.Explain(device, "Системный ID");

        Assert.Contains("идентификатор поставщика", vidPid, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("не определяют уникальный экземпляр", vidPid, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Plug and Play Windows", instanceId, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Converter_does_not_open_empty_or_unknown_tooltips()
    {
        var converter = new CellExplanationToolTipConverter();

        Assert.Null(converter.Convert(
            [DependencyProperty.UnsetValue, "Тип"],
            typeof(string),
            null!,
            CultureInfo.InvariantCulture));
        Assert.Null(converter.Convert(
            [new object(), "Неизвестный столбец"],
            typeof(string),
            null!,
            CultureInfo.InvariantCulture));
    }

    private static void AssertAllColumns(object row, IEnumerable<string> headers)
    {
        foreach (var header in headers)
        {
            var explanation = CellExplanationText.Explain(row, header);
            Assert.False(string.IsNullOrWhiteSpace(explanation), $"Нет подсказки для «{header}».");
            Assert.Contains(header, explanation, StringComparison.Ordinal);
            Assert.Contains("Значение:", explanation, StringComparison.Ordinal);
            Assert.Contains("Что это значит:", explanation, StringComparison.Ordinal);
            Assert.DoesNotContain('\0', explanation);
            Assert.InRange(explanation!.Length, 80, 1800);
        }
    }
}
