using System.Windows;
using System.Diagnostics;
using System.IO;

namespace UsbForensicAudit;

/// <summary>
/// Жёсткая трассировка Procmon: запись обращений процесса сторонней утилиты
/// к реестру как доказательство источника её данных. Отдельный файл —
/// у трассировки свой жизненный цикл (подготовка, запись, разбор CSV)
/// и своё состояние (результаты по ключам строк).
/// </summary>
public partial class MainWindow
{
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

        if (_vm.IsProcmonTracing)
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

        var runningUtility = RunningUtilityLocator.Resolve(
            row.UtilityName,
            RunningExternalUtilitiesList.SelectedItem as RunningExternalUtility,
            _runningExternalUtilities,
            _lastCapturedExternalUtility);
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

        if (!await _exclusiveOperation.WaitAsync(0))
        {
            ProcmonTraceStatusText.Text = "Другая длительная операция уже выполняется.";
            return;
        }

        _vm.IsProcmonTracing = true;
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
                progress,
                _lifetimeCancellation.Token);

            _vm.ExternalUtilities.RecordProcmonResult(row, result.Hits, result.SessionDirectory, result.SummaryForReport);

            _vm.ExternalUtilities.RefreshAssessments();
            ApplyExternalUtilityRowAssessment(row);
            ExternalUtilityStatusText.Text =
                $"Procmon завершён: {result.Hits.Count} совпадений, событий в CSV: {result.ParsedEventCount}. Папка: {result.SessionDirectory}";
            ProcmonTraceStatusText.Text = ExternalUtilityStatusText.Text;
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            ProcmonTraceStatusText.Text = "Трассировка отменена.";
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Procmon trace failed");
            ProcmonTraceStatusText.Text = ex.Message;
            ExternalUtilityStatusText.Text = ex.Message;

            var failedSession = RunningUtilityLocator.ExtractProcmonSessionDirectory(ex.Message);
            if (!string.IsNullOrWhiteSpace(failedSession) && Directory.Exists(failedSession))
            {
                _vm.ExternalUtilities.RecordProcmonSessionDirectory(row, failedSession);
                OpenProcmonSessionFolderButton.IsEnabled = true;
            }

            MessageBox.Show(this, ex.Message, "Procmon — ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _vm.IsProcmonTracing = false;
            UpdateExternalUtilityControls();
            _exclusiveOperation.Release();
        }
    }

    private void OpenProcmonSessionFolderButton_Click(object sender, RoutedEventArgs e)
    {
        if (GetExternalUtilityRowForActions() is not ExternalUtilityRow row)
        {
            return;
        }

        if (!_vm.ExternalUtilities.TryGetProcmonSessionDirectory(row, out var sessionDirectory)
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
}
