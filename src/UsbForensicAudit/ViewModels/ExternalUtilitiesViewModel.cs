using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using CommunityToolkit.Mvvm.ComponentModel;

namespace UsbForensicAudit;

/// <summary>
/// Состояние и логика подсистемы сторонних утилит (USBDetector / USBDeview / USB Oblivion):
/// строки таблицы, procmon-доказательства и оценка строк. Ничего не знает о контролах —
/// окно только отображает результат и вызывает методы. Выделен из code-behind MainWindow,
/// чтобы самая сложная логика вкладки была тестируемой без UI.
/// </summary>
public partial class ExternalUtilitiesViewModel : ObservableObject
{
    private readonly IExternalUtilityRegistryTracer? _registryTracer;
    private readonly Func<AuditResult?> _currentAuditResult;

    private readonly Dictionary<string, IReadOnlyList<ExternalUtilitySourceHit>> _procmonHitsByRowKey = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _procmonSessionByRowKey = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _procmonSummaryByRowKey = new(StringComparer.Ordinal);

    public ExternalUtilitiesViewModel(
        Func<AuditResult?> currentAuditResult,
        IExternalUtilityRegistryTracer? registryTracer = null)
    {
        _currentAuditResult = currentAuditResult;
        _registryTracer = registryTracer;
    }

    public ObservableCollection<ExternalUtilityRow> Rows { get; } = [];

    public ObservableCollection<RunningExternalUtility> RunningUtilities { get; } = [];

    public ObservableCollection<HistoricalUtilityLaunch> HistoricalLaunches { get; } = [];

    /// <summary>Фиксирует доказательства procmon-трассировки для строки таблицы.</summary>
    public void RecordProcmonResult(
        ExternalUtilityRow row,
        IReadOnlyList<ExternalUtilitySourceHit> hits,
        string sessionDirectory,
        string summaryForReport)
    {
        var rowKey = ExternalUtilityRowKey.Build(row);
        _procmonHitsByRowKey[rowKey] = hits;
        _procmonSessionByRowKey[rowKey] = sessionDirectory;
        _procmonSummaryByRowKey[rowKey] = summaryForReport;
    }

    /// <summary>
    /// Запоминает папку сессии procmon без результатов — используется, когда
    /// трассировка упала, но частичная сессия на диске осталась.
    /// </summary>
    public void RecordProcmonSessionDirectory(ExternalUtilityRow row, string sessionDirectory) =>
        _procmonSessionByRowKey[ExternalUtilityRowKey.Build(row)] = sessionDirectory;

    public bool TryGetProcmonSessionDirectory(ExternalUtilityRow row, [NotNullWhen(true)] out string? sessionDirectory) =>
        _procmonSessionByRowKey.TryGetValue(ExternalUtilityRowKey.Build(row), out sessionDirectory);

    /// <summary>Полная оценка строки с учётом procmon-доказательств и текущего аудита.</summary>
    public ExternalUtilityRowAssessment Assess(ExternalUtilityRow row)
    {
        var rowKey = ExternalUtilityRowKey.Build(row);
        _procmonHitsByRowKey.TryGetValue(rowKey, out var procmonHits);
        _procmonSessionByRowKey.TryGetValue(rowKey, out var procmonSession);
        _procmonSummaryByRowKey.TryGetValue(rowKey, out var procmonSummary);
        return ExternalUtilityRowExplainer.Assess(
            row, _currentAuditResult(), procmonHits, procmonSession, procmonSummary, _registryTracer);
    }

    /// <summary>Пересчитывает вердикты всех строк — после захвата, ручного ввода или procmon.</summary>
    public void RefreshAssessments()
    {
        foreach (var row in Rows)
        {
            ApplyAssessmentToRow(row, Assess(row));
        }
    }

    /// <summary>Переносит вычисленную оценку в отображаемые поля строки таблицы.</summary>
    public static void ApplyAssessmentToRow(ExternalUtilityRow row, ExternalUtilityRowAssessment assessment)
    {
        row.AnalysisText = assessment.FullExplanation;
        row.VerdictDisplayText = assessment.VerdictTitle;
        row.VidPidText = assessment.Identifier.VidPidText;
        row.VendorProductText = assessment.Identifier.VendorProductText;
    }

    /// <summary>Краткий разбор строки для панели «Разбор» — маркированный список главного.</summary>
    public static string BuildBriefAnalysis(ExternalUtilityRowAssessment assessment, ExternalUtilityRow row)
    {
        var lines = new List<string>
        {
            $"• Откуда строка: {assessment.ProbableOrigin}",
            $"• Замечание: {assessment.UsbDetectorNote}",
            $"• Аудит: {assessment.AuditMatchSummary}"
        };

        if (assessment.Identifier.HasVid)
        {
            lines.Add($"• VID/PID: {assessment.Identifier.VidPidText} · {assessment.Identifier.VendorProductText}");
        }

        if (assessment.HasProcmonEvidence)
        {
            lines.Insert(0, "• Procmon: жёстко зафиксировано чтение реестра процессом утилиты.");
        }

        if (ExternalUtilitySectionCatalog.IsOtherTracesSection(row.SectionTitle))
        {
            lines.Add("• Раздел «Другие следы»: косвенные ключи Windows; одна строка ≠ доказательство флешки.");
        }

        return string.Join(Environment.NewLine, lines);
    }
}
