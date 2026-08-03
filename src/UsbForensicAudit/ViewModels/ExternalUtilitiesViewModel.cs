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
    private readonly string _dataDirectory;
    private readonly IExternalUtilityRegistryTracer? _registryTracer;
    private readonly Func<AuditResult?> _currentAuditResult;

    private ExternalUtilityReportSnapshot _snapshot = new();

    private readonly Dictionary<string, IReadOnlyList<ExternalUtilitySourceHit>> _procmonHitsByRowKey = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _procmonSessionByRowKey = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _procmonSummaryByRowKey = new(StringComparer.Ordinal);

    public ExternalUtilitiesViewModel(
        string dataDirectory,
        Func<AuditResult?> currentAuditResult,
        IExternalUtilityRegistryTracer? registryTracer = null)
    {
        _dataDirectory = dataDirectory;
        _currentAuditResult = currentAuditResult;
        _registryTracer = registryTracer;
    }

    public ObservableCollection<ExternalUtilityRow> Rows { get; } = [];

    public ObservableCollection<RunningExternalUtility> RunningUtilities { get; } = [];

    public ObservableCollection<HistoricalUtilityLaunch> HistoricalLaunches { get; } = [];

    /// <summary>
    /// Строка, разбор которой открыт на панели «Разбор». Может отличаться от
    /// выделенной в таблице: пользователь мог сменить выделение, не открывая разбор.
    /// </summary>
    [ObservableProperty]
    private ExternalUtilityRow? _activeRow;

    /// <summary>Полный текст последнего разбора — для кнопки «Скопировать разбор».</summary>
    [ObservableProperty]
    private string _analysisCopyText = "";

    /// <summary>Утилита, из окна которой считывали в последний раз — кандидат для procmon-трассировки.</summary>
    [ObservableProperty]
    private RunningExternalUtility? _lastCapturedUtility;

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

    /// <summary>Загружает сохранённый снапшот с диска — вызывается при старте окна.</summary>
    public void LoadSnapshotFromDisk() =>
        _snapshot = ExternalUtilitySnapshotStorage.Load(_dataDirectory) ?? new ExternalUtilityReportSnapshot();

    /// <summary>Восстанавливает строки и историю запусков из снапшота в наблюдаемые коллекции.</summary>
    public void RestoreFromSnapshot()
    {
        Rows.Clear();
        foreach (var row in _snapshot.Rows)
        {
            Rows.Add(row);
        }

        RefreshAssessments();

        HistoricalLaunches.Clear();
        foreach (var launch in _snapshot.HistoricalLaunches)
        {
            HistoricalLaunches.Add(launch);
        }
    }

    /// <summary>
    /// Переносит текущие строки в снапшот и сохраняет его на диск.
    /// Запись идёт вне UI-потока; ошибки уходят в app.log и не прерывают работу.
    /// </summary>
    public Task SaveSnapshotAsync(string? utilityName)
    {
        _snapshot.CapturedAtUtc = DateTimeOffset.UtcNow;
        _snapshot.UtilityName = utilityName;
        _snapshot.Rows.Clear();
        foreach (var row in Rows)
        {
            _snapshot.Rows.Add(row);
        }

        return PersistSnapshotAsync();
    }

    /// <summary>Обновляет историю запусков утилит из результатов аудита и сохраняет снапшот.</summary>
    public void RefreshHistoricalLaunches(AuditResult? result)
    {
        HistoricalLaunches.Clear();
        foreach (var launch in ExternalUtilityHistoryService.CollectFromAudit(result))
        {
            HistoricalLaunches.Add(launch);
        }

        _snapshot.HistoricalLaunches.Clear();
        foreach (var launch in HistoricalLaunches)
        {
            _snapshot.HistoricalLaunches.Add(launch);
        }

        if (HistoricalLaunches.Count > 0 || _snapshot.Rows.Count > 0)
        {
            _ = PersistSnapshotAsync();
        }
    }

    /// <summary>Снапшот для вложения в отчёты; null, когда показывать нечего.</summary>
    public ExternalUtilityReportSnapshot? SnapshotForReport =>
        _snapshot.Rows.Count == 0 && _snapshot.HistoricalLaunches.Count == 0 ? null : _snapshot;

    private Task PersistSnapshotAsync()
    {
        // Отсоединённая копия: пока файл пишется в фоне, пользователь может
        // добавить строку — фоновая сериализация не должна видеть эти правки.
        var copy = new ExternalUtilityReportSnapshot
        {
            CapturedAtUtc = _snapshot.CapturedAtUtc,
            UtilityName = _snapshot.UtilityName
        };
        copy.Rows.AddRange(_snapshot.Rows);
        copy.HistoricalLaunches.AddRange(_snapshot.HistoricalLaunches);

        return Task.Run(() =>
        {
            try
            {
                ExternalUtilitySnapshotStorage.Save(_dataDirectory, copy);
            }
            catch (Exception exception)
            {
                AppLog.Error(exception, "External utility snapshot save failed");
            }
        });
    }
}
