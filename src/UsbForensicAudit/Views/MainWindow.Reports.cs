using System.Diagnostics;
using System.IO;
using System.Windows;

namespace UsbForensicAudit;

/// <summary>
/// Генерация отчётов из результата последнего сканирования. Шесть кнопок —
/// одна механика: снять снапшот сторонних утилит, построить файл в фоне,
/// открыть его. Отдельный файл, чтобы однотипные обработчики не раздували
/// основной code-behind.
/// </summary>
public partial class MainWindow
{
    private async void ManagerPdfReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.LastResult is null)
        {
            return;
        }

        var result = _vm.LastResult;
        var snapshot = GetExternalUtilitySnapshotForReport();
        await RunReportAsync(
            () => _vm.ReportService.CreateManagerPdf(result, _vm.Storage.DataDirectory, snapshot),
            "Отчёт для руководителя создан",
            "Manager PDF creation failed",
            "Ошибка PDF");
    }

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

    private async void TimelineCsvButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.LastResult is null)
        {
            return;
        }

        var result = _vm.LastResult;
        await RunReportAsync(
            () => _vm.ReportService.CreateTimelineCsv(result, _vm.Storage.DataDirectory),
            "Таймлайн (CSV) создан",
            "Timeline CSV creation failed",
            "Ошибка CSV");
    }

    private async void EvidencePackageButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.LastResult is null)
        {
            return;
        }

        var result = _vm.LastResult;
        var snapshot = GetExternalUtilitySnapshotForReport();
        await RunReportAsync(
            () => BuildEvidencePackage(result, snapshot),
            "Пакет доказательств собран",
            "Evidence package creation failed",
            "Ошибка сборки пакета");
    }

    /// <summary>
    /// Полный передаваемый пакет: свежие HTML/PDF/CSV-отчёты, база сессий и
    /// журнал доказательств, манифест SHA-256. Оператор и номер дела берутся
    /// из карточки дела (case.json), если она заполнена.
    /// </summary>
    private string BuildEvidencePackage(AuditResult result, ExternalUtilityReportSnapshot? snapshot)
    {
        var directory = _vm.Storage.DataDirectory;
        var html = _vm.ReportService.CreateHtml(result, directory, snapshot);
        var pdf = _vm.ReportService.CreatePdf(result, directory, snapshot);
        var csv = _vm.ReportService.CreateTimelineCsv(result, directory);

        var caseMetadata = CaseMetadataProvider.LoadDefault();
        var archivePath = Path.Combine(
            directory,
            $"UsbForensicAudit_Paket_{DateDisplay.ToMoscow(DateTimeOffset.UtcNow):yyyyMMdd_HHmmss}.zip");

        var package = EvidencePackageBuilder.Build(
            archivePath,
            [html, pdf, csv, _vm.Storage.DatabasePath, Path.Combine(directory, "evidence.jsonl")],
            caseMetadata.Examiner,
            caseMetadata.CaseNumber);

        return package.ArchivePath;
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
