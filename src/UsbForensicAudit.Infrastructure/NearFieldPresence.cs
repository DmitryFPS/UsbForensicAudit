using Microsoft.Win32;

namespace UsbForensicAudit;

/// <summary>
/// Есть ли на машине NFC.
///
/// Про NFC отчёт обязан сказать прямо, есть ли оборудование. Умолчание читается
/// как «по NFC ничего не передавали», хотя означать может «передавать было
/// нечем»: у настольных машин считывателя NFC нет вовсе. Разница важна, потому
/// что при наличии считывателя пустота в следах — это уже вопрос к проверке, а
/// при его отсутствии вопроса нет.
///
/// Отдельно стоит сказать и то, что даже работающий считыватель истории обмена
/// не ведёт: Windows не пишет, какая метка была поднесена и что с неё считали.
/// </summary>
internal static class NearFieldPresence
{
    private const string EnumPath = @"SYSTEM\CurrentControlSet\Enum";
    private const string ServicesPath = @"SYSTEM\CurrentControlSet\Services";

    private static readonly string[] DriverServices =
        ["NfcCx", "nfc", "NFCProximity", "ProximityUxHost", "NfcRadioMedia", "WudfNfcCx"];

    /// <summary>Перечислители устройств, которые появляются вместе со считывателем.</summary>
    private static readonly string[] Enumerators = ["NFC", "NFCSE", "SMARTCARDREADER"];

    internal static EvidenceRecord Describe()
    {
        var found = new List<string>();
        var checkedPaths = new List<string>();

        foreach (var service in DriverServices)
        {
            checkedPaths.Add($@"HKLM\{ServicesPath}\{service}");
            if (Exists($@"{ServicesPath}\{service}"))
            {
                found.Add($"драйвер {service}");
            }
        }

        foreach (var enumerator in Enumerators)
        {
            checkedPaths.Add($@"HKLM\{EnumPath}\{enumerator}");
            if (Exists($@"{EnumPath}\{enumerator}", out var count))
            {
                found.Add(count > 0
                    ? $"перечисление {enumerator}: устройств — {count}"
                    : $"перечисление {enumerator} без устройств");
            }
        }

        var absent = found.Count == 0;
        return new EvidenceRecord
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            Source = "Реестр Windows — оборудование NFC",
            EvidenceCategory = "NFC на этой машине",
            EvidenceStrength = "Context",
            Confidence = "High",
            CanEstablishConnectionDate = false,
            Summary = absent
                ? "Считывателя NFC на машине нет: ни драйверов, ни устройств не найдено."
                : $"Признаки NFC найдены: {string.Join(", ", found)}.",
            UserExplanation = absent
                ? "Проверены ветки драйверов и перечислений устройств, которые Windows создаёт при "
                  + "установке считывателя NFC. Ни одной из них нет, поэтому обмена по NFC на этой "
                  + "машине быть не могло, и пустота в следах NFC вопросов не вызывает."
                : "Оборудование NFC на машине есть. Что именно через него передавали, установить "
                  + "нельзя: Windows не ведёт журнала поднесённых метк и считанных данных. Проверять "
                  + "остаётся по следам приложений, которые с этим считывателем работали.",
            Provenance = string.Join("; ", checkedPaths)
        };
    }

    private static bool Exists(string path) => Exists(path, out _);

    private static bool Exists(string path, out int childCount)
    {
        childCount = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            if (key is null)
            {
                return false;
            }

            childCount = key.SubKeyCount;
            return true;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Закрытая от чтения ветка существует, и это уже ответ на вопрос.
            return true;
        }
    }
}
