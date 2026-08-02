using System.Windows;
using System.Diagnostics;

namespace UsbForensicAudit;

/// <summary>
/// Генерация отчётов из результата последнего сканирования. Шесть кнопок —
/// одна механика: снять снапшот сторонних утилит, построить файл в фоне,
/// открыть его. Отдельный файл, чтобы однотипные обработчики не раздували
/// основной code-behind.
/// </summary>
public partial class MainWindow
{
    private async void PdfReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.LastResult is null)
        {
            return;
        }

        var result = _vm.LastResult;
        var snapshot = GetExternalUtilitySnapshotForReport();
        await RunReportAsync(
            () => _vm.ReportService.CreatePdf(result, _vm.Storage.DataDirectory, snapshot),
            "PDF отчет создан",
            "PDF creation failed",
            "Ошибка PDF");
    }

    private async void BriefPdfReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.LastResult is null)
        {
            return;
        }

        var result = _vm.LastResult;
        var snapshot = GetExternalUtilitySnapshotForReport();
        await RunReportAsync(
            () => _vm.ReportService.CreateBriefPdf(result, _vm.Storage.DataDirectory, snapshot),
            "Сводный PDF создан",
            "Brief PDF creation failed",
            "Ошибка PDF");
    }

    private async void AnalystNotePdfReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.LastResult is null)
        {
            return;
        }

        var result = _vm.LastResult;
        var snapshot = GetExternalUtilitySnapshotForReport();
        await RunReportAsync(
            () => _vm.ReportService.CreateAnalystNotePdf(result, _vm.Storage.DataDirectory, snapshot),
            "Аналитическая записка создана",
            "Analyst note PDF creation failed",
            "Ошибка PDF");
    }

    private async void ExcelReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.LastResult is null)
        {
            return;
        }

        var result = _vm.LastResult;
        var snapshot = GetExternalUtilitySnapshotForReport();
        await RunReportAsync(
            () => _vm.ReportService.CreateExcel(result, _vm.Storage.DataDirectory, snapshot),
            "Полный Excel создан",
            "Excel creation failed",
            "Ошибка Excel");
    }

    private async void BriefExcelReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.LastResult is null)
        {
            return;
        }

        var result = _vm.LastResult;
        var snapshot = GetExternalUtilitySnapshotForReport();
        await RunReportAsync(
            () => _vm.ReportService.CreateBriefExcel(result, _vm.Storage.DataDirectory, snapshot),
            "Сводный Excel создан",
            "Brief Excel creation failed",
            "Ошибка Excel");
    }

    private async void AnalystNoteExcelReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.LastResult is null)
        {
            return;
        }

        var result = _vm.LastResult;
        var snapshot = GetExternalUtilitySnapshotForReport();
        await RunReportAsync(
            () => _vm.ReportService.CreateAnalystNoteExcel(result, _vm.Storage.DataDirectory, snapshot),
            "Аналитическая записка (Excel) создана",
            "Analyst note Excel creation failed",
            "Ошибка Excel");
    }

    private async Task RunReportAsync(
        Func<string> createReport,
        string successText,
        string errorContext,
        string errorTitle)
    {
        if (!await _exclusiveOperation.WaitAsync(0))
        {
            ReportStatusText.Text = "Другая длительная операция уже выполняется.";
            return;
        }

        try
        {
            SetBusy(true);
            var path = await Task.Run(createReport, _lifetimeCancellation.Token);
            ReportStatusText.Text = $"{successText}: {path}";
            _vm.ReportService.OpenFile(path);
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            ReportStatusText.Text = "Создание отчёта отменено.";
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, errorContext);
            MessageBox.Show(this, ex.Message, errorTitle, MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false);
            _exclusiveOperation.Release();
        }
    }

    private void OpenDataFolderButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = _vm.Storage.DataDirectory,
                UseShellExecute = true
            });
        }
        catch (Exception exception)
        {
            AppLog.Error(exception, "Open data directory failed");
            MessageBox.Show(this, exception.Message, "Не удалось открыть папку", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
