using System.Globalization;
using Microsoft.Win32;

namespace UsbForensicAudit;

/// <summary>
/// Ищет в реестре следы того, что систему развернули из подготовленного образа.
/// Разделы читаются по отдельности: недоступность одного не должна отменять
/// проверку остальных.
/// </summary>
public sealed class WindowsReferenceImageDetector : IReferenceImageDetector
{
    public ReferenceImageTrace Detect(IEnumerable<UsbDeviceRecord> devices, List<string> warnings) =>
        ReferenceImageDetector.Detect(devices, warnings);
}

public static class ReferenceImageDetector
{
    /// <summary>
    /// Производители гипервизоров. Если их устройства встречаются в истории, но
    /// сама машина не виртуальная, значит образ собирали в виртуальной машине.
    /// </summary>
    private static readonly string[] HypervisorMarkers =
    [
        "VMWARE", "VBOX", "VIRTUALBOX", "QEMU", "HYPER-V", "VMBUS", "PARALLELS", "XEN"
    ];

    public static ReferenceImageTrace Detect(IEnumerable<UsbDeviceRecord> devices, List<string> warnings)
    {
        var trace = new ReferenceImageTrace();
        ReadCloneTag(trace, warnings);
        ReadSysprepStatus(trace, warnings);
        ReadSetupType(trace, warnings);
        DetectHypervisorResidue(trace, devices);
        return trace;
    }

    /// <summary>
    /// CloneTag записывается при подготовке образа утилитой sysprep и содержит
    /// дату клонирования. Само наличие раздела — прямое доказательство образа.
    /// </summary>
    private static void ReadCloneTag(ReferenceImageTrace trace, List<string> warnings)
    {
        try
        {
            using var setup = Registry.LocalMachine.OpenSubKey(@"SYSTEM\Setup");
            if (setup?.GetValue("CloneTag") is not string[] tags || tags.Length == 0)
            {
                return;
            }

            var dates = tags
                .Select(ParseCloneTagDate)
                .Where(x => x.HasValue)
                .Select(x => x!.Value)
                .OrderBy(x => x)
                .ToArray();

            if (dates.Length > 0)
            {
                trace.PreparedAtUtc = dates[0];
            }

            trace.Add(
                "Отметка клонирования образа",
                "В разделе SYSTEM\\Setup есть CloneTag — отметка, которую оставляет sysprep при "
                + "подготовке образа к тиражированию. Записи: " + string.Join("; ", tags),
                isDecisive: true);
        }
        catch (Exception ex)
        {
            warnings.Add($"Не удалось прочитать отметку клонирования образа: {ex.Message}");
        }
    }

    private static void ReadSysprepStatus(ReferenceImageTrace trace, List<string> warnings)
    {
        try
        {
            using var status = Registry.LocalMachine.OpenSubKey(@"SYSTEM\Setup\Status\SysprepStatus");
            if (status is null)
            {
                return;
            }

            // 7 означает, что образ был обобщён sysprep /generalize и подготовлен к тиражированию.
            if (status.GetValue("GeneralizationState") is int state && state == 7)
            {
                trace.Add(
                    "Образ обобщён утилитой sysprep",
                    "GeneralizationState = 7: с системы сняты уникальные идентификаторы, "
                    + "чтобы её можно было развернуть на множество машин.",
                    isDecisive: true);
            }

            if (status.GetValue("CleanupState") is int cleanup && cleanup == 2)
            {
                trace.Add(
                    "Завершена подготовка образа",
                    "CleanupState = 2: этап очистки перед снятием образа пройден полностью.",
                    isDecisive: false);
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Не удалось прочитать состояние sysprep: {ex.Message}");
        }
    }

    private static void ReadSetupType(ReferenceImageTrace trace, List<string> warnings)
    {
        try
        {
            using var setup = Registry.LocalMachine.OpenSubKey(@"SYSTEM\Setup");
            if (setup?.GetValue("SystemSetupInProgress") is int inProgress && inProgress != 0)
            {
                trace.Add(
                    "Установка ещё не завершена",
                    "Система сообщает, что этап установки не закончен. Часть следов может "
                    + "относиться к развёртыванию, а не к работе пользователя.",
                    isDecisive: false);
            }

            if (setup?.GetValue("OOBEInProgress") is int oobe && oobe != 0)
            {
                trace.Add(
                    "Не пройдена первичная настройка",
                    "Система находится на этапе первого запуска после развёртывания.",
                    isDecisive: false);
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Не удалось прочитать состояние установки: {ex.Message}");
        }
    }

    /// <summary>
    /// Виртуальные устройства в истории физической машины означают, что образ
    /// собирали в виртуальной машине, а её следы уехали вместе с образом.
    /// </summary>
    private static void DetectHypervisorResidue(ReferenceImageTrace trace, IEnumerable<UsbDeviceRecord> devices)
    {
        var records = devices as IReadOnlyList<UsbDeviceRecord> ?? devices.ToArray();
        var virtualDevices = records
            .Where(x => HypervisorMarkers.Any(marker =>
                x.DeviceInstanceId.Contains(marker, StringComparison.OrdinalIgnoreCase)
                || x.HardwareIds.Contains(marker, StringComparison.OrdinalIgnoreCase)
                || x.FriendlyName.Contains(marker, StringComparison.OrdinalIgnoreCase)
                || x.Manufacturer.Contains(marker, StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        if (virtualDevices.Length == 0)
        {
            return;
        }

        var runningInVirtualMachine = records.Any(x =>
            x.IsCurrentlyConnected && x.Classification.Equals("Virtual", StringComparison.OrdinalIgnoreCase));
        if (runningInVirtualMachine)
        {
            return;
        }

        trace.Add(
            "Следы виртуальной машины в истории",
            "В реестре остались устройства гипервизора, хотя сейчас машина работает не в "
            + "виртуальной среде: " + string.Join(", ", virtualDevices
                .Select(x => x.DisplayName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(5))
            + ". Скорее всего, образ собирали в виртуальной машине.",
            isDecisive: false);
    }

    /// <summary>
    /// Дата в CloneTag записана в формате, который пишет sysprep, например
    /// «Sun Jul 27 06:33:56 2026». Разбор через инвариантную культуру, потому
    /// что месяц и день недели там всегда по-английски.
    /// </summary>
    internal static DateTimeOffset? ParseCloneTagDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string[] formats =
        [
            "MMM d HH:mm:ss yyyy",
            "MMM dd HH:mm:ss yyyy",
            "yyyy-MM-ddTHH:mm:ss",
            "yyyy-MM-dd HH:mm:ss"
        ];

        // День недели отбрасывается: в отметках он иногда не совпадает с самой
        // датой, и строгий разбор из-за этого отказывается читать верную дату.
        var parts = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 5)
        {
            parts = parts[1..];
        }

        var text = string.Join(' ', parts);
        foreach (var format in formats)
        {
            if (DateTime.TryParseExact(text, format, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            {
                return new DateTimeOffset(parsed, TimeSpan.Zero);
            }
        }

        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var fallback)
            ? fallback
            : null;
    }
}
