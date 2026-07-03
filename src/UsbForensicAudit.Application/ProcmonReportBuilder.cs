namespace UsbForensicAudit;

internal static class ProcmonReportBuilder
{
    public static string BuildSummary(
        ExternalUtilityRow row,
        ExternalUtilityIdentifierInfo identifier,
        IReadOnlyList<ExternalUtilitySourceHit> hits)
    {
        var top = hits[0];
        var idText = identifier.HasFullPair
            ? $"VID {identifier.Vid}/PID {identifier.Pid}"
            : identifier.HasVid
                ? $"VID {identifier.Vid}"
                : row.PrimaryText;

        var timeText = top.ObservedAtUtc is null
            ? "время не определено"
            : DateDisplay.FormatMoscow(top.ObservedAtUtc);

        var sourceKind = top.ResultText.Contains("прямой", StringComparison.OrdinalIgnoreCase)
            ? "прямой ключ реестра USB"
            : top.ResultText.Contains("косвен", StringComparison.OrdinalIgnoreCase)
                ? "косвенный ключ Windows"
                : "запись реестра";

        return
            $"Procmon: процесс {row.UtilityName} ({top.Operation}) обратился к {sourceKind} «{top.RegistryPath}» " +
            $"({timeText}). Это источник строки «{row.PrimaryText}» ({idText}) в разделе «{row.SectionTitle}». " +
            "Фиксируется факт чтения реестра утилитой, а не доказательство подключения физической флешки.";
    }
}
