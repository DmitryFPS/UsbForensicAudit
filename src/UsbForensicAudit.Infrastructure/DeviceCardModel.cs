namespace UsbForensicAudit;

/// <summary>Строка досье устройства: подпись, значение и участие в компактной карточке PDF.</summary>
internal sealed record DeviceCardField(string Label, string? Value, bool InCompactCard = true);

/// <summary>
/// Единственный источник набора полей «досье устройства» для HTML- и PDF-отчётов.
/// До выделения HTML (ForensicReportBuilder) и PDF (ForensicPdfReport) перечисляли
/// поля независимо и уже разошлись: новое поле приходилось добавлять в двух местах,
/// а подписи дат отличались. Значения возвращаются сырыми — экранирование
/// (HtmlEncode или ReportText.ForPdf) остаётся на рендерере.
/// </summary>
internal static class DeviceCardModel
{
    /// <summary>
    /// Полный список полей досье в порядке отображения. HTML показывает все;
    /// компактная карточка PDF — только поля с InCompactCard (тип и источник
    /// записи PDF выносит в цветную шапку карточки).
    /// </summary>
    public static IReadOnlyList<DeviceCardField> FieldsOf(UsbDeviceRecord device) =>
    [
        new("Тип", device.CategoryText, InCompactCard: false),
        new("Назначение", device.UserMeaning),
        new("Источник записи", device.SourceText, InCompactCard: false),
        new("Тип записи", device.DeviceTypeText, InCompactCard: false),
        new("Приносили ли с собой", device.ExternalityText, InCompactCard: false),
        new("Что это", device.DeviceKindText, InCompactCard: false),
        new("Как подключалось", device.TransportDisplayText, InCompactCard: false),
        new(
            "Внешнее или встроенное",
            $"{device.OriginDisplayText} ({DeviceKindResolver.DescribeConfidence(device.ClassificationConfidence)})",
            InCompactCard: false),
        new("На чём основан вывод", device.ClassificationEvidenceText, InCompactCard: false),
        new("Технические коды классификации", device.ClassificationCodesText, InCompactCard: false),
        new("Производитель", device.ManufacturerText),
        new("Модель", device.ModelText),
        new("VID/PID", device.VidPidText),
        new("Серийный номер", device.SerialText),
        new("Доверие к идентификаторам", device.IdentityTrustText, InCompactCard: false),
        new("Container ID", device.ContainerId),
        new("Canonical device", $"{device.CanonicalDeviceId} ({device.IdentityConfidence})"),
        new("Связанные source IDs", string.Join("; ", device.LinkedSourceIds)),
        new("Когда подключали", device.FirstConnectedText),
        new("Последняя активность", device.LastSeenText),
        new("Когда отключали", device.LastDisconnectedText),
        new("Пояснение по датам", device.DateConfidenceText),
        new("Расположение", device.LocationDisplayText),
        new("Буквы дисков", device.DriveLetters),
        new("Подключено сейчас", device.IsCurrentlyConnected ? "да" : "нет"),
        new("Системный ID", device.DeviceInstanceId)
    ];

    /// <summary>Поля компактной карточки PDF — в виде пар для AddKeyValueGrid.</summary>
    public static IReadOnlyList<(string Key, string? Value)> CompactFieldsOf(UsbDeviceRecord device) =>
        FieldsOf(device)
            .Where(field => field.InCompactCard)
            .Select(field => (Key: field.Label, field.Value))
            .ToArray();

    /// <summary>
    /// Колонки таблицы «Связанные доказательства»: подписи для всех рендереров,
    /// относительные веса колонок — для табличного рендера (PDF).
    /// </summary>
    public static readonly IReadOnlyList<(string Header, float Weight)> EvidenceColumns =
    [
        ("Дата и время", 1.2f),
        ("Категория", 1.1f),
        ("Источник", 1.1f),
        ("Сила / уверенность", 1f),
        ("Событие", 0.7f),
        ("Описание", 2.9f)
    ];

    /// <summary>Ячейки строки «Связанных доказательств» в порядке EvidenceColumns.</summary>
    public static string[] EvidenceRowOf(EvidenceRecord evidence) =>
    [
        evidence.TimestampText,
        evidence.EvidenceCategoryText,
        evidence.SourceText,
        $"{evidence.EvidenceStrength} / {evidence.Confidence}",
        evidence.EventId,
        evidence.SummaryText
    ];
}
