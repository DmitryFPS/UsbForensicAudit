using System.Windows;
using System.IO;
using System.Windows.Controls;

namespace UsbForensicAudit;

/// <summary>
/// Работа со сторонними утилитами (USBDetector, USBDeview, USB Oblivion):
/// поиск запущенных процессов, считывание их окон, разбор строк, ручной ввод,
/// снапшот для отчётов. Отдельный файл — это самостоятельная подсистема
/// со своим состоянием и своей вкладкой интерфейса.
/// </summary>
public partial class MainWindow
{
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
            RefreshHistoricalUtilityLaunches(_vm.LastResult);
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

    private void RunningExternalUtilitiesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        CaptureExternalUtilityButton.IsEnabled = RunningExternalUtilitiesList.SelectedItem is RunningExternalUtility
                                                   && AdminHelper.IsAdministrator()
                                                   && !_vm.IsScanning;
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

        if (!await _exclusiveOperation.WaitAsync(0))
        {
            ExternalUtilityStatusText.Text = "Другая длительная операция уже выполняется.";
            return;
        }

        try
        {
            SetBusy(true);
            ExternalUtilityStatusText.Text = $"Считывание «{selected.DisplayName}» без переключения окон…";
            var capture = await ExternalUtilityCaptureRunner.CaptureAsync(selected, _lifetimeCancellation.Token);

            _externalUtilityRows.Clear();
            foreach (var section in capture.Sections)
            {
                foreach (var row in section.Rows)
                {
                    _externalUtilityRows.Add(row);
                }
            }

            _vm.ExternalUtilities.RefreshAssessments();
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
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            ExternalUtilityStatusText.Text = "Считывание отменено.";
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
            _exclusiveOperation.Release();
        }
    }

    private void ExternalUtilityRowsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var hasRow = ExternalUtilityRowsGrid.SelectedItem is ExternalUtilityRow;
        CopyExternalUtilityRowButton.IsEnabled = hasRow;
        FillManualFromRowButton.IsEnabled = hasRow && AdminHelper.IsAdministrator() && !_vm.IsScanning;
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

    private void ExternalUtilitySectionFilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
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

        var selected = ExternalUtilitySectionFilterCombo.SelectedItem as ComboBoxItem;
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
        var selected = (ExternalUtilitySectionFilterCombo.SelectedItem as ComboBoxItem)?.Content?.ToString();
        ExternalUtilitySectionFilterCombo.Items.Clear();
        ExternalUtilitySectionFilterCombo.Items.Add(new ComboBoxItem { Content = "Все разделы" });

        foreach (var section in _externalUtilityRows.Select(x => x.SectionTitle).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x))
        {
            ExternalUtilitySectionFilterCombo.Items.Add(new ComboBoxItem { Content = section });
        }

        if (!string.IsNullOrWhiteSpace(selected))
        {
            var match = ExternalUtilitySectionFilterCombo.Items
                .Cast<ComboBoxItem>()
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
        var selected = (ExternalUtilitySectionFilterCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Все разделы";
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

    private ExternalUtilityRow? GetExternalUtilityRowForActions() =>
        ExternalUtilityRowsGrid.SelectedItem as ExternalUtilityRow ?? _activeExternalUtilityRow;

    private void ApplyExternalUtilityRowAssessment(ExternalUtilityRow row)
    {
        _activeExternalUtilityRow = row;
        var assessment = _vm.ExternalUtilities.Assess(row);
        ExternalUtilitiesViewModel.ApplyAssessmentToRow(row, assessment);

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
        ExternalUtilityBriefAnalysisText.Text = ExternalUtilitiesViewModel.BuildBriefAnalysis(assessment, row);
        ExternalUtilitySelectedRowSummaryText.Text =
            $"{row.SectionTitle}{Environment.NewLine}{row.FormattedDetailsText}";
        _lastExternalUtilityAnalysisCopyText = assessment.FullExplanation;
        CopyExternalUtilityAnalysisButton.IsEnabled = true;
        UpdateExternalUtilityControls();
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
        _vm.ExternalUtilities.RefreshAssessments();
        RefreshExternalUtilitySectionFilterCombo();
        _externalUtilityRowsView.Refresh();
        ExternalUtilityRowsGrid.SelectedItem = row;
        ApplyExternalUtilityRowAssessment(row);
        ExternalUtilityStatusText.Text = "Строка из ручного ввода добавлена. Откройте вкладку «Разбор» для подробностей.";
        SaveExternalUtilitySnapshot("Ручной ввод");
        ExternalUtilityInnerTabs.SelectedItem = ExternalUtilityAnalysisTab;
    }

    private void RefreshHistoricalUtilityLaunches(AuditResult? result)
    {
        _vm.ExternalUtilities.RefreshHistoricalLaunches(result);
        HistoricalUtilityLaunchesList.ItemsSource = _historicalUtilityLaunches;
    }

    private void SaveExternalUtilitySnapshot(string? utilityName) =>
        _ = _vm.ExternalUtilities.SaveSnapshotAsync(utilityName);

    private void RestoreExternalUtilitySnapshotToUi()
    {
        _vm.ExternalUtilities.RestoreFromSnapshot();
        RefreshExternalUtilitySectionFilterCombo();
        _externalUtilityRowsView.Refresh();
        HistoricalUtilityLaunchesList.ItemsSource = _historicalUtilityLaunches;
    }

    private ExternalUtilityReportSnapshot? GetExternalUtilitySnapshotForReport() =>
        _vm.ExternalUtilities.SnapshotForReport;

    private void UpdateExternalUtilityControls()
    {
        var isAdmin = AdminHelper.IsAdministrator();
        FindExternalUtilitiesButton.IsEnabled = isAdmin && !_vm.IsScanning;
        CaptureExternalUtilityButton.IsEnabled = isAdmin
                                                 && !_vm.IsScanning
                                                 && RunningExternalUtilitiesList?.SelectedItem is RunningExternalUtility;
        AnalyzeManualUtilityButton.IsEnabled = isAdmin && !_vm.IsScanning;
        CopyExternalUtilityRowButton.IsEnabled = ExternalUtilityRowsGrid?.SelectedItem is ExternalUtilityRow;
        FillManualFromRowButton.IsEnabled = isAdmin
                                              && !_vm.IsScanning
                                              && ExternalUtilityRowsGrid?.SelectedItem is ExternalUtilityRow;
        CopyExternalUtilityAnalysisButton.IsEnabled = !string.IsNullOrWhiteSpace(_lastExternalUtilityAnalysisCopyText);
        OpenExternalUtilityAnalysisTabButton.IsEnabled = GetExternalUtilityRowForActions() is ExternalUtilityRow
                                                       || ExternalUtilityRowsGrid?.SelectedItem is ExternalUtilityRow;
        ProcmonTraceButton.IsEnabled = !_vm.IsProcmonTracing
                                       && GetExternalUtilityRowForActions() is ExternalUtilityRow;
        if (!isAdmin && ExternalUtilityStatusText is not null && string.IsNullOrWhiteSpace(ExternalUtilityStatusText.Text))
        {
            ExternalUtilityStatusText.Text = "Для работы с USBDetector / USBDeview запустите программу от администратора.";
        }
    }
}
