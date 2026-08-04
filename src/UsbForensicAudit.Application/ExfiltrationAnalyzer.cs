namespace UsbForensicAudit;

/// <summary>
/// Выделяет из признаков переноса файлов ответ на главный вопрос расследования
/// утечки: какие файлы вынесли с машины на съёмные носители. Опирается на уже
/// вычисленные <see cref="CopyIndication"/> (их проставляет FileCopyAnalyzer в
/// ходе аудита), поэтому анализ чистый, детерминированный и тестируется без ФС.
/// </summary>
public static class ExfiltrationAnalyzer
{
    public static ExfiltrationSummary Analyze(AuditResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var outbound = new List<ExfiltrationItem>();
        var undirectedItems = new List<ExfiltrationItem>();

        foreach (var device in result.Devices)
        {
            foreach (var indication in device.CopyIndications)
            {
                if (indication.Direction == CopyDirection.ToDevice)
                {
                    outbound.Add(BuildItem(device, indication, isUndirected: false));
                }
                else if (indication.Direction == CopyDirection.Unknown)
                {
                    // Раньше такие признаки учитывались только числом и не показывались
                    // в таблице. Но разница событий меньше 10 минут — самое сильное
                    // свидетельство переноса; скрывать эти строки значило прятать
                    // главный ответ на вопрос «копировали ли файлы на носитель».
                    undirectedItems.Add(BuildItem(device, indication, isUndirected: true));
                }
            }
        }

        // Сортировка отражает следственный приоритет: сначала подтверждённое
        // журналом, затем более свежее — с него разумно начинать разбор.
        return new ExfiltrationSummary
        {
            OutboundFiles = Sort(outbound),
            UndirectedFiles = Sort(undirectedItems),
            JournalAvailable = result.FileChangeJournals.Count > 0
        };
    }

    private static ExfiltrationItem BuildItem(UsbDeviceRecord device, CopyIndication indication, bool isUndirected) => new()
    {
        FileName = indication.FileName,
        DeviceDisplayName = device.DisplayName,
        DeviceId = string.IsNullOrEmpty(device.CanonicalDeviceId)
            ? device.DeviceInstanceId
            : device.CanonicalDeviceId,
        // Момент появления на устройстве — время самого выноса; если его нет,
        // берём локальную отметку, чтобы строка не осталась без времени вовсе.
        WhenUtc = indication.SeenOnDeviceUtc ?? indication.SeenLocallyUtc,
        Confidence = indication.Confidence,
        Basis = indication.Basis,
        IsUndirected = isUndirected
    };

    private static List<ExfiltrationItem> Sort(List<ExfiltrationItem> items)
    {
        return items
            .OrderByDescending(x => x.IsConfirmed)
            .ThenByDescending(x => x.WhenUtc ?? DateTimeOffset.MinValue)
            .ThenBy(x => x.FileName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
