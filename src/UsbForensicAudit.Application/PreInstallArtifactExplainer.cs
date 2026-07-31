namespace UsbForensicAudit;

/// <summary>
/// Часть артефактов датирована раньше, чем установлена сама Windows. На первый
/// взгляд это противоречие, и читатель отчёта либо считает такую запись
/// ошибкой программы, либо, наоборот, делает из неё вывод о работе за машиной
/// до установки системы. Оба вывода неверны, и объяснить это должна программа,
/// а не читатель.
///
/// Штампы Shimcache, Amcache и ярлыков — это время последнего изменения самого
/// файла, а не время его запуска. Файл переживает переустановку системы на
/// другом разделе, приезжает вместе с перенесённым профилем или копируется с
/// сохранением даты, поэтому спокойно оказывается старше текущей установки.
/// </summary>
public static class PreInstallArtifactExplainer
{
    /// <summary>
    /// Источники, у которых штамп времени берётся из метаданных файла, а не из
    /// события. Только для них расхождение с датой установки объяснимо и не
    /// является признаком подделки времени.
    /// </summary>
    private static readonly string[] FileTimestampSources =
    [
        "Shimcache", "AppCompatCache", "Amcache", "Ярлыки пользователя", "Jump Lists",
        "Recycle Bin", "Prefetch"
    ];

    public static void Explain(AuditResult result)
    {
        if (!result.OsInstalledAtUtc.HasValue)
        {
            return;
        }

        var installed = result.OsInstalledAtUtc.Value;
        var explained = 0;

        foreach (var evidence in result.Evidence)
        {
            if (evidence.TimestampUtc >= installed
                || !DateDisplay.IsReliable(evidence.TimestampUtc)
                || !UsesFileTimestamp(evidence.Source))
            {
                continue;
            }

            evidence.UserExplanation = Append(evidence.UserExplanation, Describe(evidence, installed, result));
            explained++;
        }

        if (explained > 0)
        {
            result.SourceWarnings.Add(
                $"Записей со штампом раньше установки Windows: {explained}. "
                + "Это не сбой: у таких источников штамп берётся из метаданных файла, а не из события. "
                + "Каждая запись снабжена пояснением.");
        }
    }

    private static string Describe(EvidenceRecord evidence, DateTimeOffset installed, AuditResult result)
    {
        var text =
            $"Штамп записи ({DateDisplay.FormatMoscow(evidence.TimestampUtc)}) старше установки Windows "
            + $"({DateDisplay.FormatMoscow(installed)}). Противоречия здесь нет: {SourceKind(evidence.Source)} "
            + "хранит время последнего изменения файла, а не время его запуска. Файл мог остаться на "
            + "несистемном разделе после переустановки, приехать вместе с перенесённым профилем или быть "
            + "скопированным с сохранением исходной даты. Считать эту дату временем работы программы за "
            + "этой машиной нельзя.";

        var prepared = result.ReferenceImage.PreparedAtUtc;
        if (prepared.HasValue && evidence.TimestampUtc >= prepared.Value)
        {
            text += $" Штамп при этом новее подготовки эталонного образа ({DateDisplay.FormatMoscow(prepared)}), "
                    + "поэтому объяснить запись одним лишь образом тоже нельзя: скорее всего, файл лежит на "
                    + "разделе, который переустановка не затронула.";
        }

        return text;
    }

    private static string SourceKind(string source) =>
        source.Contains("Shimcache", StringComparison.OrdinalIgnoreCase)
        || source.Contains("AppCompatCache", StringComparison.OrdinalIgnoreCase)
            ? "Shimcache"
            : source.Contains("Amcache", StringComparison.OrdinalIgnoreCase)
                ? "Amcache"
                : "этот источник";

    private static bool UsesFileTimestamp(string source) =>
        FileTimestampSources.Any(x => source.Contains(x, StringComparison.OrdinalIgnoreCase));

    private static string Append(string existing, string addition) =>
        string.IsNullOrWhiteSpace(existing) ? addition : $"{existing} {addition}";
}
