using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Data;

namespace UsbForensicAudit;

public partial class MainWindow : Window
{
    private readonly AuditOrchestrator _orchestrator = new();
    private readonly ReportService _reportService = new();
    private readonly WmiUsbMonitor _monitor = new();
    private readonly DeviceChangeNotifier _deviceChangeNotifier;
    private readonly LiveUsbSnapshotService _liveUsbSnapshotService = new();
    private readonly ObservableCollection<UsbDeviceRecord> _devices = [];
    private readonly ObservableCollection<EvidenceRecord> _evidence = [];
    private readonly ObservableCollection<CleanupFinding> _cleanupFindings = [];
    private readonly ObservableCollection<ExternalUtilityRow> _externalUtilityRows = [];
    private readonly ObservableCollection<RunningExternalUtility> _runningExternalUtilities = [];
    private readonly ObservableCollection<HistoricalUtilityLaunch> _historicalUtilityLaunches = [];
    private readonly ICollectionView _cleanupFindingsView;
    private readonly ICollectionView _externalUtilityRowsView;
    private ExternalUtilityReportSnapshot _externalUtilitySnapshot = new();
    private AuditResult? _lastResult;
    private string _lastExternalUtilityAnalysisCopyText = "";
    private bool _isScanning;
    private bool _isProcmonTracing;
    private ExternalUtilityRow? _activeExternalUtilityRow;
    private RunningExternalUtility? _lastCapturedExternalUtility;
    private readonly Dictionary<string, IReadOnlyList<ExternalUtilitySourceHit>> _procmonHitsByRowKey = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _procmonSessionByRowKey = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _procmonSummaryByRowKey = new(StringComparer.Ordinal);
    private DateTimeOffset _lastAutoScanUtc = DateTimeOffset.MinValue;
    private ActiveDevicesWindow? _activeDevicesWindow;

    public ObservableCollection<UsbDeviceRecord> Devices => _devices;
    public ObservableCollection<EvidenceRecord> Evidence => _evidence;
    public ObservableCollection<CleanupFinding> CleanupFindings => _cleanupFindings;
    public ObservableCollection<ExternalUtilityRow> ExternalUtilityRows => _externalUtilityRows;

    public MainWindow()
    {
        InitializeComponent();
        ApplyHeaderLogo();
        TrySetWindowIconInstance();
        _deviceChangeNotifier = new DeviceChangeNotifier(this);
        _monitor.AttachDeviceNotifier(_deviceChangeNotifier);
        DataContext = this;
        _cleanupFindingsView = CollectionViewSource.GetDefaultView(_cleanupFindings);
        _cleanupFindingsView.Filter = FilterCleanupFinding;
        FindingsGrid.ItemsSource = _cleanupFindingsView;
        _externalUtilityRowsView = CollectionViewSource.GetDefaultView(_externalUtilityRows);
        _externalUtilityRowsView.Filter = FilterExternalUtilityRow;
        ExternalUtilityRowsGrid.ItemsSource = _externalUtilityRowsView;
        _externalUtilitySnapshot = ExternalUtilitySnapshotStorage.Load(_orchestrator.Storage.DataDirectory) ?? new ExternalUtilityReportSnapshot();
        RestoreExternalUtilitySnapshotToUi();
        RefreshExternalUtilitySectionFilterCombo();
        AdminStatusText.Text = AdminHelper.IsAdministrator() ? "Администратор" : "Нет прав администратора";
        ElevateButton.Visibility = AdminHelper.IsAdministrator() ? Visibility.Collapsed : Visibility.Visible;
        UpdateOsInstallDisplay(null);
        AppendLog($"Запуск UsbForensicAudit. Администратор: {AdminHelper.IsAdministrator()}. {AppPaths.LayoutDescription}");
        AppendLog($"База: {_orchestrator.Storage.DatabasePath}");
        UpdateExternalUtilityControls();
        _monitor.DeviceChanged += Monitor_DeviceChanged;
        _monitor.RefreshRequested += Monitor_RefreshRequested;
    }

    private void ApplyHeaderLogo()
    {
        HeaderLogoImage.Source = AppBranding.LoadLogo(decodePixelWidth: 256);
    }

    private void TrySetWindowIconInstance()
    {
        try
        {
            Icon = AppBranding.LoadLogo(decodePixelWidth: 48);
        }
        catch
        {
            // Icon is optional.
        }
    }

    private void ElevateButton_Click(object sender, RoutedEventArgs e)
    {
        AdminHelper.TryRestartElevated(this);
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        await RunScanAsync("Полное сканирование запущено.");
    }

    private async Task RunScanAsync(string startMessage)
    {
        if (_isScanning)
        {
            AppendLog("Сканирование уже выполняется, новый запуск пропущен.");
            return;
        }

        try
        {
            _isScanning = true;
            SetBusy(true);
            AppendLog(startMessage);
            AppLog.Info(startMessage);
            var progress = new Progress<string>(message =>
            {
                StatusText.Text = message;
                AppendLog(message);
            });

            var result = await _orchestrator.RunFullScanAsync(progress);
            _lastResult = result;
            BindResult(result);
            PdfReportButton.IsEnabled = true;
            BriefPdfReportButton.IsEnabled = true;
            AppendLog($"Дата установки Windows: {result.OsInstalledAtText}.");
            var suspiciousCount = result.CleanupFindings.Count(x => x.IsSuspicious);
            AppendLog($"Готово: устройств {result.Devices.Count}, доказательств {result.Evidence.Count}, записей об очистке {result.CleanupFindings.Count} (подозрительных {suspiciousCount}).");
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Scan failed");
            AppendLog($"Ошибка сканирования: {ex}");
            MessageBox.Show(this, ex.Message, "Ошибка сканирования", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _isScanning = false;
            SetBusy(false);
            StatusText.Text = "Готово";
        }
    }

    private void BindResult(AuditResult result)
    {
        _devices.Clear();
        foreach (var item in result.Devices.OrderBy(x => CategoryRank(x.VisualCategory)).ThenBy(x => x.DisplayName))
        {
            _devices.Add(item);
        }

        _evidence.Clear();
        foreach (var item in result.Evidence.OrderByDescending(x => x.TimestampUtc))
        {
            _evidence.Add(item);
        }

        _cleanupFindings.Clear();
        foreach (var item in result.CleanupFindings
                     .OrderByDescending(x => x.IsSuspicious)
                     .ThenByDescending(x => SeverityRank(x.Severity))
                     .ThenByDescending(x => x.TimestampUtc))
        {
            _cleanupFindings.Add(item);
        }

        DevicesCountText.Text = _devices.Count.ToString();
        EvidenceCountText.Text = _evidence.Count.ToString();
        var suspiciousCount = result.CleanupFindings.Count(x => x.IsSuspicious);
        FindingsCountText.Text = suspiciousCount.ToString();
        FindingsSubText.Text = result.CleanupFindings.Count == 0
            ? "Подозрительных записей нет"
            : $"Всего записей: {result.CleanupFindings.Count}, подозрительных: {suspiciousCount}";
        UpdateOsInstallDisplay(result);
        RefreshHistoricalUtilityLaunches(result);
        RefreshExternalUtilityRowAssessments();
        RefreshExternalUtilitySectionFilterCombo();
        DataGridAutoSize.FitColumns(DevicesGrid);
        DataGridAutoSize.FitColumns(EvidenceGrid);
        DataGridAutoSize.FitColumns(FindingsGrid);
        _cleanupFindingsView.Refresh();
    }

    private void UpdateOsInstallDisplay(AuditResult? result)
    {
        var installAtUtc = result?.OsInstalledAtUtc ?? OsInstallInfo.GetInstalledAtUtc();
        var scanAtUtc = result?.StartedAtUtc ?? DateTimeOffset.UtcNow;
        var installText = OsInstallInfo.FormatInstallDate(installAtUtc);
        var graceText = OsInstallInfo.GracePeriodExplanation(installAtUtc, scanAtUtc);

        OsInstallDateText.Text = installText;
        OsInstallGraceText.Text = graceText;
        CleanupOsInstallDateText.Text = installText;
        CleanupGraceText.Text = graceText;
    }

    private void MonitorButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _deviceChangeNotifier.Start();
            _monitor.Start();
            ShowAndRefreshActiveDevicesWindow();
            MonitorButton.IsEnabled = false;
            StopMonitorButton.IsEnabled = true;
            ShowActiveDevicesButton.IsEnabled = true;
            AppendLog("Live-мониторинг запущен. Обновление идёт по событиям Windows, без постоянного опроса каждые 2 секунды.");
            if (!string.IsNullOrWhiteSpace(EndpointProtectionEnvironment.Summary))
            {
                AppendLog(EndpointProtectionEnvironment.Summary);
            }
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Monitor start failed");
            MessageBox.Show(this, ex.Message, "Ошибка запуска мониторинга", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void StopMonitorButton_Click(object sender, RoutedEventArgs e)
    {
        _deviceChangeNotifier.Stop();
        _monitor.Stop();
        MonitorButton.IsEnabled = true;
        StopMonitorButton.IsEnabled = false;
        ShowActiveDevicesButton.IsEnabled = false;
        AppendLog("Live-мониторинг остановлен.");
    }

    private void ShowActiveDevicesButton_Click(object sender, RoutedEventArgs e)
    {
        ShowAndRefreshActiveDevicesWindow();
        AppendLog("Окно текущих USB/Type-C устройств открыто.");
    }

    private void Monitor_RefreshRequested(object? sender, EventArgs e)
    {
        Dispatcher.Invoke(RefreshActiveDevicesWindow);
    }

    private async void Monitor_DeviceChanged(object? sender, string e)
    {
        await Dispatcher.InvokeAsync(async () =>
        {
            AppendLog(e);
            await Task.Delay(800);
            RefreshActiveDevicesWindow();

            if (DateTimeOffset.UtcNow - _lastAutoScanUtc < TimeSpan.FromSeconds(15))
            {
                return;
            }

            _lastAutoScanUtc = DateTimeOffset.UtcNow;
            await RunScanAsync("Автоснимок после изменения USB.");
        });
    }

    private void ShowAndRefreshActiveDevicesWindow()
    {
        if (!IsActiveDevicesWindowOpen())
        {
            _activeDevicesWindow = new ActiveDevicesWindow
            {
                Owner = this
            };
            _activeDevicesWindow.Closed += ActiveDevicesWindow_Closed;
            _activeDevicesWindow.Show();
        }
        else
        {
            _activeDevicesWindow!.Activate();
            if (_activeDevicesWindow.WindowState == WindowState.Minimized)
            {
                _activeDevicesWindow.WindowState = WindowState.Normal;
            }
        }

        RefreshActiveDevicesWindow();
    }

    private bool IsActiveDevicesWindowOpen()
    {
        return _activeDevicesWindow is { IsVisible: true };
    }

    private void ActiveDevicesWindow_Closed(object? sender, EventArgs e)
    {
        if (sender is ActiveDevicesWindow window)
        {
            window.Closed -= ActiveDevicesWindow_Closed;
        }

        _activeDevicesWindow = null;
    }

    private void RefreshActiveDevicesWindow()
    {
        if (!StopMonitorButton.IsEnabled)
        {
            return;
        }

        try
        {
            if (!IsActiveDevicesWindowOpen())
            {
                return;
            }

            _activeDevicesWindow!.UpdateDevices(_liveUsbSnapshotService.GetCurrentDevices());
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Active USB snapshot failed");
            AppendLog($"Не удалось обновить окно текущих USB: {ex.Message}");
        }
    }

    private void PdfReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult is null)
        {
            return;
        }

        try
        {
            var path = _reportService.CreatePdf(_lastResult, _orchestrator.Storage.DataDirectory, GetExternalUtilitySnapshotForReport());
            ReportStatusText.Text = $"PDF отчет создан: {path}";
            _reportService.OpenFile(path);
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "PDF creation failed");
            MessageBox.Show(this, ex.Message, "Ошибка PDF", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void BriefPdfReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult is null)
        {
            return;
        }

        try
        {
            var path = _reportService.CreateBriefPdf(_lastResult, _orchestrator.Storage.DataDirectory, GetExternalUtilitySnapshotForReport());
            ReportStatusText.Text = $"Сводный PDF создан: {path}";
            _reportService.OpenFile(path);
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Brief PDF creation failed");
            MessageBox.Show(this, ex.Message, "Ошибка PDF", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OpenDataFolderButton_Click(object sender, RoutedEventArgs e)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = _orchestrator.Storage.DataDirectory,
            UseShellExecute = true
        });
    }

    private void FindExternalUtilitiesButton_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureAdministratorForExternalUtilities())
        {
            return;
        }

        try
        {
            _runningExternalUtilities.Clear();
            foreach (var utility in RunningExternalUtilityScanner.Scan())
            {
                _runningExternalUtilities.Add(utility);
            }

            RunningExternalUtilitiesList.ItemsSource = _runningExternalUtilities;
            RefreshHistoricalUtilityLaunches(_lastResult);
            CaptureExternalUtilityButton.IsEnabled = _runningExternalUtilities.Count > 0;
            ExternalUtilityStatusText.Text = _runningExternalUtilities.Count == 0
                ? "Запущенные USBDetector / USBDeview / USB Oblivion не найдены. Сначала откройте утилиту и выполните в ней поиск."
                : $"Найдено утилит: {_runningExternalUtilities.Count}. Выберите нужную и нажмите «Считать результат из окна».";
            AppendLog($"Поиск сторонних утилит: найдено {_runningExternalUtilities.Count}.");
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "External utility scan failed");
            MessageBox.Show(this, ex.Message, "Сторонние утилиты", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void RunningExternalUtilitiesList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        CaptureExternalUtilityButton.IsEnabled = RunningExternalUtilitiesList.SelectedItem is RunningExternalUtility
                                                   && AdminHelper.IsAdministrator()
                                                   && !_isScanning;
    }

    private async void CaptureExternalUtilityButton_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureAdministratorForExternalUtilities())
        {
            return;
        }

        if (RunningExternalUtilitiesList.SelectedItem is not RunningExternalUtility selected)
        {
            MessageBox.Show(this, "Сначала выберите утилиту в списке слева.", "Сторонние утилиты", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            SetBusy(true);
            ExternalUtilityStatusText.Text = $"Считывание «{selected.DisplayName}» без переключения окон…";
            var capture = await ExternalUtilityCaptureRunner.CaptureAsync(selected);

            _externalUtilityRows.Clear();
            foreach (var section in capture.Sections)
            {
                foreach (var row in section.Rows)
                {
                    _externalUtilityRows.Add(row);
                }
            }

            RefreshExternalUtilityRowAssessments();
            RefreshExternalUtilitySectionFilterCombo();
            _externalUtilityRowsView.Refresh();

            AppendLog($"Считан результат {capture.DisplayName}: {_externalUtilityRows.Count} строк.");
            SaveExternalUtilitySnapshot(capture.DisplayName);
            _lastCapturedExternalUtility = selected;
            DataGridAutoSize.FitColumns(ExternalUtilityRowsGrid);

            var preferredRow = _externalUtilityRows.FirstOrDefault(r => r.IsOtherTracesSection)
                               ?? _externalUtilityRows.FirstOrDefault();
            if (preferredRow is not null)
            {
                ExternalUtilityRowsGrid.SelectedItem = preferredRow;
                ApplyExternalUtilityRowAssessment(preferredRow);
                ExternalUtilityInnerTabs.SelectedItem = ExternalUtilityAnalysisTab;
                ExternalUtilityStatusText.Text =
                    $"Считано из «{capture.DisplayName}»: {capture.Sections.Count} таблиц, {_externalUtilityRows.Count} строк. " +
                    "Можно сразу нажать «Жёсткая трассировка (Procmon)» — USBDetector должен остаться открытым.";
            }
            else
            {
                ExternalUtilityInnerTabs.SelectedIndex = 1;
                ExternalUtilityStatusText.Text =
                    $"Считано из «{capture.DisplayName}»: {capture.Sections.Count} таблиц, {_externalUtilityRows.Count} строк.";
            }

            UpdateExternalUtilityControls();
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "External utility capture failed");
            ExternalUtilityStatusText.Text = ex.Message;
            MessageBox.Show(this, ex.Message, "Сторонние утилиты", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void ExternalUtilityRowsGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        var hasRow = ExternalUtilityRowsGrid.SelectedItem is ExternalUtilityRow;
        CopyExternalUtilityRowButton.IsEnabled = hasRow;
        FillManualFromRowButton.IsEnabled = hasRow && AdminHelper.IsAdministrator() && !_isScanning;
        OpenExternalUtilityAnalysisTabButton.IsEnabled = hasRow;

        if (ExternalUtilityRowsGrid.SelectedItem is not ExternalUtilityRow row)
        {
            return;
        }

        ApplyExternalUtilityRowAssessment(row);
        UpdateExternalUtilityControls();
    }

    private void OpenExternalUtilityAnalysisTabButton_Click(object sender, RoutedEventArgs e)
    {
        var row = GetExternalUtilityRowForActions() ?? ExternalUtilityRowsGrid.SelectedItem as ExternalUtilityRow;
        if (row is null)
        {
            ExternalUtilityStatusText.Text = "Сначала выберите строку на вкладке «Данные».";
            ExternalUtilityInnerTabs.SelectedIndex = 1;
            return;
        }

        ApplyExternalUtilityRowAssessment(row);
        ExternalUtilityInnerTabs.SelectedItem = ExternalUtilityAnalysisTab;
        UpdateExternalUtilityControls();
    }

    private void ExternalUtilitySectionFilterCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        _externalUtilityRowsView?.Refresh();
        UpdateExternalUtilitySectionInfoPanel();
    }

    private bool FilterExternalUtilityRow(object item)
    {
        if (item is not ExternalUtilityRow row)
        {
            return false;
        }

        var selected = ExternalUtilitySectionFilterCombo.SelectedItem as System.Windows.Controls.ComboBoxItem;
        var filter = selected?.Content?.ToString() ?? "Все разделы";
        return filter switch
        {
            "Основной список (реестр)" => row.SectionTitle.Contains("Основной список", StringComparison.OrdinalIgnoreCase),
            "Другие следы подключения устройств" => row.IsOtherTracesSection,
            _ => true
        };
    }

    private void RefreshExternalUtilitySectionFilterCombo()
    {
        var selected = (ExternalUtilitySectionFilterCombo.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString();
        ExternalUtilitySectionFilterCombo.Items.Clear();
        ExternalUtilitySectionFilterCombo.Items.Add(new System.Windows.Controls.ComboBoxItem { Content = "Все разделы" });

        foreach (var section in _externalUtilityRows.Select(x => x.SectionTitle).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x))
        {
            ExternalUtilitySectionFilterCombo.Items.Add(new System.Windows.Controls.ComboBoxItem { Content = section });
        }

        if (!string.IsNullOrWhiteSpace(selected))
        {
            var match = ExternalUtilitySectionFilterCombo.Items
                .Cast<System.Windows.Controls.ComboBoxItem>()
                .FirstOrDefault(x => string.Equals(x.Content?.ToString(), selected, StringComparison.OrdinalIgnoreCase));
            ExternalUtilitySectionFilterCombo.SelectedItem = match ?? ExternalUtilitySectionFilterCombo.Items[0];
        }
        else
        {
            ExternalUtilitySectionFilterCombo.SelectedIndex = 0;
        }

        UpdateExternalUtilitySectionInfoPanel();
    }

    private void UpdateExternalUtilitySectionInfoPanel()
    {
        var selected = (ExternalUtilitySectionFilterCombo.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "Все разделы";
        if (selected == "Все разделы")
        {
            ExternalUtilitySectionInfoTitle.Text = "Все разделы";
            ExternalUtilitySectionInfoSummary.Text =
                "Сначала смотрите «Основной список (реестр)» — там прямые записи USB. " +
                "«Другие следы» — отдельно: это косвенные записи, не каждая строка = реальная флешка.";
            ExternalUtilitySectionInfoReliability.Text =
                "Выберите конкретный раздел в списке, чтобы увидеть пояснение и фильтровать таблицу.";
            return;
        }

        var info = ExternalUtilitySectionCatalog.GetInfo(selected);
        ExternalUtilitySectionInfoTitle.Text = info.Title;
        ExternalUtilitySectionInfoSummary.Text = info.Summary;
        ExternalUtilitySectionInfoReliability.Text = $"{info.Reliability} Источники: {info.TypicalSources}";
    }

    private void RefreshExternalUtilityRowAssessments()
    {
        foreach (var row in _externalUtilityRows)
        {
            var assessment = AssessExternalUtilityRow(row);
            row.AnalysisText = assessment.FullExplanation;
            row.VerdictDisplayText = assessment.VerdictTitle;
            row.VidPidText = assessment.Identifier.VidPidText;
            row.VendorProductText = assessment.Identifier.VendorProductText;
        }
    }

    private ExternalUtilityRowAssessment AssessExternalUtilityRow(ExternalUtilityRow row)
    {
        var rowKey = ExternalUtilityRowKey.Build(row);
        _procmonHitsByRowKey.TryGetValue(rowKey, out var procmonHits);
        _procmonSessionByRowKey.TryGetValue(rowKey, out var procmonSession);
        _procmonSummaryByRowKey.TryGetValue(rowKey, out var procmonSummary);
        return ExternalUtilityRowExplainer.Assess(row, _lastResult, procmonHits, procmonSession, procmonSummary);
    }

    private ExternalUtilityRow? GetExternalUtilityRowForActions() =>
        ExternalUtilityRowsGrid.SelectedItem as ExternalUtilityRow ?? _activeExternalUtilityRow;

    private void ApplyExternalUtilityRowAssessment(ExternalUtilityRow row)
    {
        _activeExternalUtilityRow = row;
        var assessment = AssessExternalUtilityRow(row);
        row.AnalysisText = assessment.FullExplanation;
        row.VerdictDisplayText = assessment.VerdictTitle;
        row.VidPidText = assessment.Identifier.VidPidText;
        row.VendorProductText = assessment.Identifier.VendorProductText;

        ExternalUtilityVerdictTitleText.Text = assessment.VerdictTitle;
        ExternalUtilityReportConclusionText.Text = assessment.ReportConclusionRow;
        ExternalUtilityReportConclusionProcmonText.Text = assessment.ReportConclusionProcmon ?? "";
        ExternalUtilityReportConclusionCaseText.Text = assessment.ReportConclusionCase;
        ExternalUtilitySourceChecksText.Text = assessment.SourceChecksText;
        ProcmonTraceStatusText.Text = assessment.HasProcmonEvidence
            ? $"Procmon: сессия сохранена в {assessment.ProcmonSessionDirectory}"
            : "Нажмите «Жёсткая трассировка (Procmon)». USBDetector должен быть открыт (как после «Считать из окна») — повторное сканирование запустится автоматически.";
        OpenProcmonSessionFolderButton.IsEnabled = !string.IsNullOrWhiteSpace(assessment.ProcmonSessionDirectory)
                                                   && Directory.Exists(assessment.ProcmonSessionDirectory);
        ExternalUtilityVidPidText.Text =
            $"VID/PID: {assessment.Identifier.VidPidText} · {assessment.Identifier.VendorProductText} ({assessment.Identifier.ParseMethod})";
        ExternalUtilityOriginText.Text = $"Откуда, скорее всего: {assessment.ProbableOrigin}";
        ExternalUtilityAuditMatchText.Text = $"Наш аудит: {assessment.AuditMatchSummary}";
        ExternalUtilityBriefAnalysisText.Text = BuildExternalUtilityBriefAnalysis(assessment, row);
        ExternalUtilitySelectedRowSummaryText.Text =
            $"{row.SectionTitle}{Environment.NewLine}{row.FormattedDetailsText}";
        _lastExternalUtilityAnalysisCopyText = assessment.FullExplanation;
        CopyExternalUtilityAnalysisButton.IsEnabled = true;
        UpdateExternalUtilityControls();
    }

    private static string BuildExternalUtilityBriefAnalysis(ExternalUtilityRowAssessment assessment, ExternalUtilityRow row)
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

    private void ResetExternalUtilityAnalysisPanel()
    {
        _activeExternalUtilityRow = null;
        ExternalUtilityVerdictTitleText.Text = "Выберите строку на вкладке «Данные»";
        ExternalUtilityReportConclusionText.Text = "";
        ExternalUtilityReportConclusionProcmonText.Text = "";
        ExternalUtilityReportConclusionCaseText.Text = "";
        ExternalUtilitySourceChecksText.Text = "";
        ProcmonTraceStatusText.Text = "";
        OpenProcmonSessionFolderButton.IsEnabled = false;
        ExternalUtilityVidPidText.Text = "";
        ExternalUtilityOriginText.Text = "";
        ExternalUtilityAuditMatchText.Text = "";
        ExternalUtilityBriefAnalysisText.Text = "";
        ExternalUtilitySelectedRowSummaryText.Text = "—";
        _lastExternalUtilityAnalysisCopyText = "";
        CopyExternalUtilityAnalysisButton.IsEnabled = false;
    }

    private async void ProcmonTraceButton_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureAdministratorForExternalUtilities())
        {
            return;
        }

        if (GetExternalUtilityRowForActions() is not ExternalUtilityRow row)
        {
            ProcmonTraceStatusText.Text = "Сначала выберите строку на вкладке «Данные» или откройте «Разбор строки →».";
            MessageBox.Show(
                this,
                "Выберите строку на вкладке «Данные» (таблица) или нажмите «Разбор строки →» для текущей записи.",
                "Procmon",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        if (_isProcmonTracing)
        {
            return;
        }

        foreach (var utility in RunningExternalUtilityScanner.Scan())
        {
            if (_runningExternalUtilities.All(x => x.ProcessId != utility.ProcessId))
            {
                _runningExternalUtilities.Add(utility);
            }
        }

        RunningExternalUtilitiesList.ItemsSource = _runningExternalUtilities;

        var runningUtility = ResolveRunningUtilityForRow(row);
        if (runningUtility is null)
        {
            const string message =
                "USBDetector/USBDeview сейчас не запущен. Procmon записывает чтения реестра только от работающего процесса.\n\n" +
                "Не закрывайте USBDetector после «Считать из окна» — затем снова нажмите «Жёсткая трассировка (Procmon)».";
            ProcmonTraceStatusText.Text = message.Replace('\n', ' ');
            ExternalUtilityStatusText.Text = "Процесс утилиты не найден — оставьте USBDetector открытым после считывания.";
            MessageBox.Show(this, message, "Procmon — утилита не запущена", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _isProcmonTracing = true;
        UpdateExternalUtilityControls();

        try
        {
            ProcmonTraceStatusText.Text = "Подготовка Procmon…";
            ExternalUtilityStatusText.Text =
                $"Procmon: запись для {runningUtility.DisplayName}. Повторное сканирование в утилите запустится автоматически (~20 сек)…";

            var progress = new Progress<string>(message =>
            {
                ProcmonTraceStatusText.Text = message;
                ExternalUtilityStatusText.Text = message;
            });

            var result = await ProcmonTraceRunner.TraceAsync(
                new ProcmonTraceRequest
                {
                    Row = row,
                    UtilityProcessName = runningUtility.ProcessName,
                    UtilityProcessId = runningUtility.ProcessId,
                    UtilityId = runningUtility.UtilityId,
                    CaptureDuration = TimeSpan.FromSeconds(20)
                },
                progress);

            var rowKey = ExternalUtilityRowKey.Build(row);
            _procmonHitsByRowKey[rowKey] = result.Hits;
            _procmonSessionByRowKey[rowKey] = result.SessionDirectory;
            _procmonSummaryByRowKey[rowKey] = result.SummaryForReport;

            RefreshExternalUtilityRowAssessments();
            ApplyExternalUtilityRowAssessment(row);
            ExternalUtilityStatusText.Text =
                $"Procmon завершён: {result.Hits.Count} совпадений, событий в CSV: {result.ParsedEventCount}. Папка: {result.SessionDirectory}";
            ProcmonTraceStatusText.Text = ExternalUtilityStatusText.Text;
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Procmon trace failed");
            ProcmonTraceStatusText.Text = ex.Message;
            ExternalUtilityStatusText.Text = ex.Message;

            var rowKey = ExternalUtilityRowKey.Build(row);
            var failedSession = ExtractProcmonSessionDirectory(ex.Message);
            if (!string.IsNullOrWhiteSpace(failedSession) && Directory.Exists(failedSession))
            {
                _procmonSessionByRowKey[rowKey] = failedSession;
                OpenProcmonSessionFolderButton.IsEnabled = true;
            }

            MessageBox.Show(this, ex.Message, "Procmon — ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _isProcmonTracing = false;
            UpdateExternalUtilityControls();
        }
    }

    private void OpenProcmonSessionFolderButton_Click(object sender, RoutedEventArgs e)
    {
        if (GetExternalUtilityRowForActions() is not ExternalUtilityRow row)
        {
            return;
        }

        var rowKey = ExternalUtilityRowKey.Build(row);
        if (!_procmonSessionByRowKey.TryGetValue(rowKey, out var sessionDirectory)
            || !Directory.Exists(sessionDirectory))
        {
            ProcmonTraceStatusText.Text = "Папка сессии Procmon для этой строки не найдена.";
            return;
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = sessionDirectory,
            UseShellExecute = true
        });
    }

    private RunningExternalUtility? ResolveRunningUtilityForRow(ExternalUtilityRow row)
    {
        if (RunningExternalUtilitiesList.SelectedItem is RunningExternalUtility selected
            && UtilityNamesMatch(row.UtilityName, selected.DisplayName, selected.ProcessName))
        {
            return TryRefreshRunningUtility(selected);
        }

        var match = _runningExternalUtilities.FirstOrDefault(u =>
            UtilityNamesMatch(row.UtilityName, u.DisplayName, u.ProcessName));
        if (match is not null)
        {
            return TryRefreshRunningUtility(match);
        }

        if (_lastCapturedExternalUtility is not null
            && UtilityNamesMatch(row.UtilityName, _lastCapturedExternalUtility.DisplayName, _lastCapturedExternalUtility.ProcessName))
        {
            var refreshed = TryRefreshRunningUtility(_lastCapturedExternalUtility);
            if (refreshed is not null)
            {
                return refreshed;
            }
        }

        var rowDefinition = ExternalUtilityCatalog.MatchProcess(row.UtilityName)
                            ?? ExternalUtilityCatalog.Definitions.FirstOrDefault(def =>
                                row.UtilityName.Contains(def.DisplayName, StringComparison.OrdinalIgnoreCase)
                                || def.DisplayName.Contains(row.UtilityName, StringComparison.OrdinalIgnoreCase));

        if (rowDefinition is null)
        {
            return null;
        }

        return _runningExternalUtilities
            .Where(u => string.Equals(u.UtilityId, rowDefinition.Id, StringComparison.OrdinalIgnoreCase))
            .Select(TryRefreshRunningUtility)
            .FirstOrDefault(u => u is not null);
    }

    private static RunningExternalUtility? TryRefreshRunningUtility(RunningExternalUtility utility)
    {
        try
        {
            using var process = Process.GetProcessById(utility.ProcessId);
            if (process.HasExited)
            {
                return null;
            }

            process.Refresh();
            return new RunningExternalUtility
            {
                UtilityId = utility.UtilityId,
                DisplayName = utility.DisplayName,
                ProcessId = process.Id,
                ProcessName = process.ProcessName,
                MainWindowTitle = process.MainWindowTitle,
                HasMainWindow = process.MainWindowHandle != IntPtr.Zero
            };
        }
        catch
        {
            var processName = Path.GetFileNameWithoutExtension(utility.ProcessName);
            var live = Process.GetProcessesByName(processName).FirstOrDefault(x => !x.HasExited);
            if (live is null)
            {
                return null;
            }

            try
            {
                live.Refresh();
                return new RunningExternalUtility
                {
                    UtilityId = utility.UtilityId,
                    DisplayName = utility.DisplayName,
                    ProcessId = live.Id,
                    ProcessName = live.ProcessName,
                    MainWindowTitle = live.MainWindowTitle,
                    HasMainWindow = live.MainWindowHandle != IntPtr.Zero
                };
            }
            finally
            {
                live.Dispose();
            }
        }
    }

    private static string? ExtractProcmonSessionDirectory(string message)
    {
        const string marker = "Файлы:";
        var index = message.LastIndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return null;
        }

        return message[(index + marker.Length)..].Trim();
    }

    private static bool UtilityNamesMatch(string rowUtilityName, string displayName, string processName)
    {
        var rowName = rowUtilityName.Trim();
        if (rowName.Contains(displayName, StringComparison.OrdinalIgnoreCase)
            || displayName.Contains(rowName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var processBase = Path.GetFileNameWithoutExtension(processName);
        var rowBase = Path.GetFileNameWithoutExtension(rowName);
        return rowName.Contains(processBase, StringComparison.OrdinalIgnoreCase)
               || processBase.Contains(rowBase, StringComparison.OrdinalIgnoreCase);
    }

    private void CopyExternalUtilityRowButton_Click(object sender, RoutedEventArgs e)
    {
        if (ExternalUtilityRowsGrid.SelectedItem is not ExternalUtilityRow row)
        {
            ExternalUtilityStatusText.Text = "Сначала выберите строку в таблице.";
            return;
        }

        try
        {
            Clipboard.SetText(row.CopyText);
            ExternalUtilityStatusText.Text = "Строка скопирована в буфер обмена (можно вставить в поле ввода или в другую программу).";
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Copy external utility row failed");
            ExternalUtilityStatusText.Text = "Не удалось скопировать строку в буфер обмена.";
        }
    }

    private void CopyExternalUtilityAnalysisButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_lastExternalUtilityAnalysisCopyText))
        {
            return;
        }

        try
        {
            Clipboard.SetText(_lastExternalUtilityAnalysisCopyText);
            ExternalUtilityStatusText.Text = "Текст разбора скопирован в буфер обмена.";
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Copy external utility analysis failed");
            ExternalUtilityStatusText.Text = "Не удалось скопировать разбор.";
        }
    }

    private void FillManualFromRowButton_Click(object sender, RoutedEventArgs e)
    {
        if (ExternalUtilityRowsGrid.SelectedItem is not ExternalUtilityRow row)
        {
            ExternalUtilityStatusText.Text = "Сначала выберите строку в таблице.";
            return;
        }

        ExternalUtilityManualInput.Text = row.CopyText;
        ExternalUtilityManualInput.Focus();
        ExternalUtilityManualInput.CaretIndex = ExternalUtilityManualInput.Text.Length;
        ExternalUtilityStatusText.Text = "Текст перенесён на вкладку «Ручной ввод».";
        ExternalUtilityInnerTabs.SelectedIndex = 3;
    }

    private bool EnsureAdministratorForExternalUtilities()
    {
        if (AdminHelper.IsAdministrator())
        {
            return true;
        }

        MessageBox.Show(
            this,
            "Считывание окна сторонней утилиты доступно только при запуске программы от администратора.",
            "Сторонние утилиты",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
        return false;
    }

    private void AnalyzeManualUtilityButton_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureAdministratorForExternalUtilities())
        {
            return;
        }

        var raw = ExternalUtilityManualInput.Text.Trim();
        if (string.IsNullOrWhiteSpace(raw))
        {
            ExternalUtilityStatusText.Text = "Вставьте или перенесите строку из таблицы в поле ввода.";
            ExternalUtilityManualInput.Focus();
            return;
        }

        var row = ExternalUtilityManualParser.Parse(raw);
        _externalUtilityRows.Add(row);
        RefreshExternalUtilityRowAssessments();
        RefreshExternalUtilitySectionFilterCombo();
        _externalUtilityRowsView.Refresh();
        ExternalUtilityRowsGrid.SelectedItem = row;
        ApplyExternalUtilityRowAssessment(row);
        ExternalUtilityStatusText.Text = "Строка из ручного ввода добавлена. Откройте вкладку «Разбор» для подробностей.";
        SaveExternalUtilitySnapshot("Ручной ввод");
        ExternalUtilityInnerTabs.SelectedItem = ExternalUtilityAnalysisTab;
    }

    private void CleanupFilterCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        _cleanupFindingsView?.Refresh();
    }

    private bool FilterCleanupFinding(object item)
    {
        if (item is not CleanupFinding finding)
        {
            return false;
        }

        var selected = (CleanupFilterCombo.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "Все записи";
        return selected switch
        {
            "Только USB-утилиты" => finding.IsUsbUtilityTool,
            "Только запуск утилит" => finding.ActionKind.Equals("ToolLaunch", StringComparison.OrdinalIgnoreCase),
            "Вероятная очистка" => finding.ActionKind.Equals("ProbableCleanup", StringComparison.OrdinalIgnoreCase)
                                    || finding.ActionKind.Equals("LogClearing", StringComparison.OrdinalIgnoreCase),
            "Только подозрительные" => finding.IsSuspicious,
            _ => true
        };
    }

    private void RefreshHistoricalUtilityLaunches(AuditResult? result)
    {
        _historicalUtilityLaunches.Clear();
        foreach (var launch in ExternalUtilityHistoryService.CollectFromAudit(result))
        {
            _historicalUtilityLaunches.Add(launch);
        }

        HistoricalUtilityLaunchesList.ItemsSource = _historicalUtilityLaunches;
        _externalUtilitySnapshot.HistoricalLaunches.Clear();
        foreach (var launch in _historicalUtilityLaunches)
        {
            _externalUtilitySnapshot.HistoricalLaunches.Add(launch);
        }

        if (_historicalUtilityLaunches.Count > 0 || _externalUtilitySnapshot.Rows.Count > 0)
        {
            ExternalUtilitySnapshotStorage.Save(_orchestrator.Storage.DataDirectory, _externalUtilitySnapshot);
        }
    }

    private void SaveExternalUtilitySnapshot(string? utilityName)
    {
        _externalUtilitySnapshot.CapturedAtUtc = DateTimeOffset.UtcNow;
        _externalUtilitySnapshot.UtilityName = utilityName;
        _externalUtilitySnapshot.Rows.Clear();
        foreach (var row in _externalUtilityRows)
        {
            _externalUtilitySnapshot.Rows.Add(row);
        }

        ExternalUtilitySnapshotStorage.Save(_orchestrator.Storage.DataDirectory, _externalUtilitySnapshot);
    }

    private void RestoreExternalUtilitySnapshotToUi()
    {
        _externalUtilityRows.Clear();
        foreach (var row in _externalUtilitySnapshot.Rows)
        {
            _externalUtilityRows.Add(row);
        }

        RefreshExternalUtilityRowAssessments();
        RefreshExternalUtilitySectionFilterCombo();
        _externalUtilityRowsView.Refresh();

        _historicalUtilityLaunches.Clear();
        foreach (var launch in _externalUtilitySnapshot.HistoricalLaunches)
        {
            _historicalUtilityLaunches.Add(launch);
        }

        HistoricalUtilityLaunchesList.ItemsSource = _historicalUtilityLaunches;
    }

    private ExternalUtilityReportSnapshot? GetExternalUtilitySnapshotForReport()
    {
        if (_externalUtilitySnapshot.Rows.Count == 0 && _externalUtilitySnapshot.HistoricalLaunches.Count == 0)
        {
            return null;
        }

        return _externalUtilitySnapshot;
    }

    private void UpdateExternalUtilityControls()
    {
        var isAdmin = AdminHelper.IsAdministrator();
        FindExternalUtilitiesButton.IsEnabled = isAdmin && !_isScanning;
        CaptureExternalUtilityButton.IsEnabled = isAdmin
                                                 && !_isScanning
                                                 && RunningExternalUtilitiesList?.SelectedItem is RunningExternalUtility;
        AnalyzeManualUtilityButton.IsEnabled = isAdmin && !_isScanning;
        CopyExternalUtilityRowButton.IsEnabled = ExternalUtilityRowsGrid?.SelectedItem is ExternalUtilityRow;
        FillManualFromRowButton.IsEnabled = isAdmin
                                              && !_isScanning
                                              && ExternalUtilityRowsGrid?.SelectedItem is ExternalUtilityRow;
        CopyExternalUtilityAnalysisButton.IsEnabled = !string.IsNullOrWhiteSpace(_lastExternalUtilityAnalysisCopyText);
        OpenExternalUtilityAnalysisTabButton.IsEnabled = GetExternalUtilityRowForActions() is ExternalUtilityRow
                                                       || ExternalUtilityRowsGrid?.SelectedItem is ExternalUtilityRow;
        ProcmonTraceButton.IsEnabled = !_isProcmonTracing
                                       && GetExternalUtilityRowForActions() is ExternalUtilityRow;
        if (!isAdmin && ExternalUtilityStatusText is not null && string.IsNullOrWhiteSpace(ExternalUtilityStatusText.Text))
        {
            ExternalUtilityStatusText.Text = "Для работы с USBDetector / USBDeview запустите программу от администратора.";
        }
    }

    private void SetBusy(bool busy)
    {
        ScanButton.IsEnabled = !busy;
        PdfReportButton.IsEnabled = !busy && _lastResult is not null;
        BriefPdfReportButton.IsEnabled = !busy && _lastResult is not null;
        UpdateExternalUtilityControls();
        Cursor = busy ? System.Windows.Input.Cursors.Wait : null;
    }

    private void AppendLog(string message)
    {
        ActivityLogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
        ActivityLogTextBox.ScrollToEnd();
    }

    private static int SeverityRank(string severity)
    {
        return severity.ToLowerInvariant() switch
        {
            "critical" => 5,
            "high" => 4,
            "medium" => 3,
            "low" => 2,
            "info" => 1,
            _ => 0
        };
    }

    private static int CategoryRank(string category)
    {
        return category switch
        {
            "RealUsb" => 0,
            "RelatedStorage" => 1,
            "SupportArtifact" => 2,
            _ => 3
        };
    }

    protected override void OnClosed(EventArgs e)
    {
        _deviceChangeNotifier.Dispose();
        _monitor.Dispose();
        _activeDevicesWindow?.Close();
        base.OnClosed(e);
    }
}