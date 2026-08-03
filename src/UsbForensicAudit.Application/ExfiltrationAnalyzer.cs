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
        var undirected = 0;

        foreach (var device in result.Devices)
        {
            foreach (var indication in device.CopyIndications)
            {
                if (indication.Direction == CopyDirection.ToDevice)
                {
                    outbound.Add(new ExfiltrationItem
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
                        Basis = indication.Basis
                    });
                }
                else if (indication.Direction == CopyDirection.Unknown)
                {
                    undirected++;
                }
            }
        }

        // Сортировка отражает следственный приоритет: сначала подтверждённое
        // журналом, затем более свежее — с него разумно начинать разбор.
        outbound = outbound
            .OrderByDescending(x => x.IsConfirmed)
            .ThenByDescending(x => x.WhenUtc ?? DateTimeOffset.MinValue)
            .ThenBy(x => x.FileName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new ExfiltrationSummary
        {
            OutboundFiles = outbound,
            UndirectedCount = undirected,
            JournalAvailable = result.FileChangeJournals.Count > 0
        };
    }
}
