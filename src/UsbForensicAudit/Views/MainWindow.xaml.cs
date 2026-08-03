using System.Windows;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;

namespace UsbForensicAudit;

/// <summary>
/// Ядро главного окна: состояние, конструктор, полное сканирование и фильтры
/// основных таблиц. Остальные подсистемы вынесены в partial-файлы:
/// Monitoring (live-события USB), Reports (генерация отчётов),
/// ExternalUtilities (считывание сторонних утилит), Procmon (трассировка).
/// </summary>
public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly WmiUsbMonitor _monitor;
    private readonly DeviceChangeNotifier _deviceChangeNotifier;
    private readonly LiveUsbSnapshotService _liveUsbSnapshotService;
    private readonly IOsInfoProvider _osInfoProvider;
    private ObservableCollection<UsbDeviceRecord> _devices => _vm.Devices;
    private ObservableCollection<EvidenceRecord> _evidence => _vm.Evidence;
    private ObservableCollection<CleanupFinding> _cleanupFindings => _vm.CleanupFindings;
    private ObservableCollection<ExternalUtilityRow> _externalUtilityRows => _vm.ExternalUtilityRows;
    private ObservableCollection<RunningExternalUtility> _runningExternalUtilities => _vm.RunningExternalUtilities;
    private ObservableCollection<HistoricalUtilityLaunch> _historicalUtilityLaunches => _vm.HistoricalUtilityLaunches;
    private readonly ICollectionView _cleanupFindingsView;
    private readonly ICollectionView _externalUtilityRowsView;
    private readonly ICollectionView _devicesView;
    private readonly ICollectionView _networkView;
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private readonly SemaphoreSlim _exclusiveOperation = new(1, 1);
    private readonly SemaphoreSlim _liveRefreshGate = new(1, 1);
    private DateTimeOffset _lastAutoScanUtc = DateTimeOffset.MinValue;
    private ActiveDevicesWindow? _activeDevicesWindow;

    public MainWindow(
        MainViewModel viewModel,
        WmiUsbMonitor monitor,
        LiveUsbSnapshotService liveUsbSnapshotService,
        IOsInfoProvider osInfoProvider)
    {
        _vm = viewModel;
        _monitor = monitor;
        _liveUsbSnapshotService = liveUsbSnapshotService;
        _osInfoProvider = osInfoProvider;
        InitializeComponent();
        ApplyHeaderLogo();
        TrySetWindowIconInstance();
        _deviceChangeNotifier = new DeviceChangeNotifier(this);
        _monitor.AttachDeviceNotifier(_deviceChangeNotifier);
        DataContext = _vm;
        _devicesView = CollectionViewSource.GetDefaultView(_devices);
        _devicesView.Filter = FilterDevice;
        DevicesGrid.ItemsSource = _devicesView;
        _networkView = CollectionViewSource.GetDefaultView(_vm.NetworkConnections);
        _networkView.Filter = FilterNetworkConnection;
        NetworkGrid.ItemsSource = _networkView;
        _cleanupFindingsView = CollectionViewSource.GetDefaultView(_cleanupFindings);
        _cleanupFindingsView.Filter = FilterCleanupFinding;
        FindingsGrid.ItemsSource = _cleanupFindingsView;
        _externalUtilityRowsView = CollectionViewSource.GetDefaultView(_externalUtilityRows);
        _externalUtilityRowsView.Filter = FilterExternalUtilityRow;
        ExternalUtilityRowsGrid.ItemsSource = _externalUtilityRowsView;
        _vm.ExternalUtilities.LoadSnapshotFromDisk();
        RestoreExternalUtilitySnapshotToUi();
        RefreshExternalUtilitySectionFilterCombo();
        AdminStatusText.Text = AdminHelper.IsAdministrator() ? "Администратор" : "Нет прав администратора";
        ElevateButton.Visibility = AdminHelper.IsAdministrator() ? Visibility.Collapsed : Visibility.Visible;
        UpdateOsInstallDisplay(null);
        AppendLog($"Запуск UsbForensicAudit. Администратор: {AdminHelper.IsAdministrator()}. {AppPaths.LayoutDescription}");
        AppendLog($"База: {_vm.Storage.DatabasePath}");
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
            // Иконка необязательна.
        }
    }

    private void ElevateButton_Click(object sender, RoutedEventArgs e)
    {
        ElevationHelper.TryRestartElevated(this);
    }

    private void DevicesGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is not DependencyObject source
            || ItemsControl.ContainerFromElement(DevicesGrid, source) is not DataGridRow row
            || row.Item is not UsbDeviceRecord device)
        {
            return;
        }

        var detailsWindow = new DeviceDetailsWindow(device, _vm.LastResult)
        {
            Owner = this
        };

        detailsWindow.ShowDialog();
        e.Handled = true;
    }

    private void DeviceFilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _devicesView?.Refresh();
        UpdateDeviceCount();
    }

    private void NetworkGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is not DependencyObject source
            || ItemsControl.ContainerFromElement(NetworkGrid, source) is not DataGridRow row
            || row.Item is not NetworkConnectionRecord connection)
        {
            return;
        }

        new NetworkConnectionDetailsWindow(connection) { Owner = this }.ShowDialog();
        e.Handled = true;
    }

    private void NetworkFilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _networkView?.Refresh();
        UpdateNetworkCount();
    }

    private bool FilterNetworkConnection(object item)
    {
        if (item is not NetworkConnectionRecord connection)
        {
            return false;
        }

        var selected = (NetworkFilterCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All";
        return selected switch
        {
            "All" => true,
            "OutsideReach" => connection.IsOutsideReach,
            _ => connection.Kind.Equals(selected, StringComparison.OrdinalIgnoreCase)
        };
    }

    /// <summary>
    /// Сколько строк показано из скольких. Без этого числа отобранный фильтром
    /// список читается как весь список связей.
    /// </summary>
    private void UpdateNetworkCount()
    {
        if (_networkView is null)
        {
            return;
        }

        var shown = _networkView.Cast<object>().Count();
        NetworkCountText.Text = shown == _vm.NetworkConnections.Count
            ? $"Связей: {shown}"
            : $"Связей: {shown} из {_vm.NetworkConnections.Count}";
    }

    private bool FilterDevice(object item)
    {
        if (item is not UsbDeviceRecord device)
        {
            return false;
        }

        // Windows описывает одно устройство несколькими записями. По умолчанию
        // список показывает устройства, а не строки реестра: услуги телефона,
        // грани составных устройств и части шины свёрнуты в свои устройства и
        // видны в окне сведений. Галочка возвращает их все — счёт строк должен
        // сходиться с реестром, иначе отчёт нечем проверить.
        if (AllRecordsCheck?.IsChecked != true && DeviceComposition.IsFoldedByDefault(device))
        {
            return false;
        }

        var selected = (DeviceFilterCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All";
        return selected switch
        {
            "All" => true,
            "ExternalOnly" => device.IsExternalDevice,
            "ExternalMedia" => device.Externality == DeviceExternality.ExternalMedia,
            _ => device.Classification.Equals(selected, StringComparison.OrdinalIgnoreCase)
                 || device.Transport.Equals(selected, StringComparison.OrdinalIgnoreCase)
                 || device.Connection.Equals(selected, StringComparison.OrdinalIgnoreCase)
        };
    }

    private void AllRecordsCheck_Changed(object sender, RoutedEventArgs e)
    {
        _devicesView?.Refresh();
        UpdateDeviceCount();
    }

    /// <summary>
    /// Сколько строк показано из скольких записей. Без этого числа свёрнутый
    /// список читается как весь список найденного.
    /// </summary>
    private void UpdateDeviceCount()
    {
        if (_devicesView is null)
        {
            return;
        }

        var shown = _devicesView.Cast<object>().Count();
        DevicesCountText.Text = shown == _devices.Count
            ? shown.ToString()
            : $"{shown} из {_devices.Count}";
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        await RunScanAsync("Полное сканирование запущено.");
    }

    private async Task RunScanAsync(string startMessage)
    {
        if (_vm.IsScanning)
        {
            AppendLog("Сканирование уже выполняется, новый запуск пропущен.");
            return;
        }

        if (!await _exclusiveOperation.WaitAsync(0))
        {
            AppendLog("Другая длительная операция уже выполняется, сканирование отложено.");
            return;
        }

        try
        {
            _vm.IsScanning = true;
            SetBusy(true);
            AppendLog(startMessage);
            AppLog.Info(startMessage);
            var progress = new Progress<string>(message =>
            {
                StatusText.Text = message;
                AppendLog(message);
            });

            var result = await _vm.RunFullScanAsync(progress, _lifetimeCancellation.Token);
            _vm.LastResult = result;
            BindResult(result);
            PdfReportButton.IsEnabled = true;
            AnalystNotePdfReportButton.IsEnabled = true;
            BriefPdfReportButton.IsEnabled = true;
            ExcelReportButton.IsEnabled = true;
            BriefExcelReportButton.IsEnabled = true;
            AnalystNoteExcelReportButton.IsEnabled = true;
            AppendLog($"Дата установки Windows: {result.OsInstalledAtText}.");
            var suspiciousCount = result.CleanupFindings.Count(x => x.IsSuspicious);
            AppendLog($"Готово: устройств {result.Devices.Count}, доказательств {result.Evidence.Count}, записей об очистке {result.CleanupFindings.Count} (подозрительных {suspiciousCount}).");
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            AppendLog("Сканирование отменено при завершении приложения.");
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Scan failed");
            AppendLog($"Ошибка сканирования: {ex}");
            MessageBox.Show(this, ex.Message, "Ошибка сканирования", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _vm.IsScanning = false;
            SetBusy(false);
            StatusText.Text = "Готово";
            _exclusiveOperation.Release();
        }
    }

    private void BindResult(AuditResult result)
    {
        _vm.PopulateFromResult(result);

        _devicesView.Refresh();
        UpdateDeviceCount();
        EvidenceCountText.Text = _evidence.Count.ToString();
        UpdateNetworkCount();
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

    private async void CaptureEnvironmentButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.IsCapturingNetworkEnvironment)
        {
            return;
        }

        if (_vm.LastResult is null)
        {
            MessageBox.Show(this,
                "Сначала выполните полное сканирование — снимок привязывается к его результату.",
                "Обстановка вокруг машины",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        CaptureEnvironmentButton.IsEnabled = false;
        ActiveProbeCheck.IsEnabled = false;
        EnvironmentStatusText.Text = "Снимаю...";
        AppendLog("Съёмка обстановки запущена.");
        try
        {
            var progress = new Progress<string>(message => EnvironmentStatusText.Text = message);
            await _vm.CaptureNetworkEnvironmentAsync(ActiveProbeCheck.IsChecked == true, progress, _lifetimeCancellation.Token);
            EnvironmentStatusText.Text = "Готово.";
            AppendLog(_vm.NetworkEnvironmentSummary);
        }
        catch (Exception ex)
        {
            EnvironmentStatusText.Text = "Ошибка.";
            AppendLog($"Ошибка съёмки обстановки: {ex.Message}");
            MessageBox.Show(this, ex.Message, "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            CaptureEnvironmentButton.IsEnabled = true;
            ActiveProbeCheck.IsEnabled = true;
        }
    }

    private void UpdateOsInstallDisplay(AuditResult? result)
    {
        var installAtUtc = result?.OsInstalledAtUtc ?? _osInfoProvider.GetInstalledAtUtc();
        var scanAtUtc = result?.StartedAtUtc ?? DateTimeOffset.UtcNow;
        var installText = OsInstallInfo.FormatInstallDate(installAtUtc);
        var graceText = OsInstallInfo.GracePeriodExplanation(installAtUtc, scanAtUtc);

        OsInstallDateText.Text = installText;
        OsInstallGraceText.Text = graceText;
        CleanupOsInstallDateText.Text = installText;
        CleanupGraceText.Text = graceText;
    }

    private void CleanupFilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _cleanupFindingsView?.Refresh();
    }

    private bool FilterCleanupFinding(object item)
    {
        if (item is not CleanupFinding finding)
        {
            return false;
        }

        var selected = (CleanupFilterCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Все записи";
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

    private void SetBusy(bool busy)
    {
        ScanButton.IsEnabled = !busy;
        PdfReportButton.IsEnabled = !busy && _vm.LastResult is not null;
        AnalystNotePdfReportButton.IsEnabled = !busy && _vm.LastResult is not null;
        BriefPdfReportButton.IsEnabled = !busy && _vm.LastResult is not null;
        ExcelReportButton.IsEnabled = !busy && _vm.LastResult is not null;
        BriefExcelReportButton.IsEnabled = !busy && _vm.LastResult is not null;
        AnalystNoteExcelReportButton.IsEnabled = !busy && _vm.LastResult is not null;
        UpdateExternalUtilityControls();
        if (busy)
        {
            CopyExternalUtilityRowButton.IsEnabled = false;
            CopyExternalUtilityAnalysisButton.IsEnabled = false;
            CaptureExternalUtilityButton.IsEnabled = false;
        }
        Cursor = busy ? Cursors.Wait : null;
    }

    private void AppendLog(string message)
    {
        ActivityLogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
        ActivityLogTextBox.ScrollToEnd();
    }

    protected override void OnClosed(EventArgs e)
    {
        _lifetimeCancellation.Cancel();
        // Явная отписка: время жизни окна не должно зависеть от того,
        // отписывает ли WmiUsbMonitor.Dispose внешних подписчиков.
        _monitor.DeviceChanged -= Monitor_DeviceChanged;
        _monitor.RefreshRequested -= Monitor_RefreshRequested;
        _deviceChangeNotifier.Dispose();
        _monitor.Dispose();
        _activeDevicesWindow?.Close();
        base.OnClosed(e);
    }
}
