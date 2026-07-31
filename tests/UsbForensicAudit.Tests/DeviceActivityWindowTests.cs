using System;
using System.Threading;
using System.Windows;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Разметка окна проверяется компилятором лишь частично: неверная привязка или
/// стиль с несуществующим типом падают только при открытии окна. Поэтому окно
/// истории здесь создаётся по-настоящему, в потоке STA.
/// </summary>
public class DeviceActivityWindowTests
{
    [Fact]
    public void Activity_window_opens_and_fills_its_tables()
    {
        var history = new DeviceActivityHistory
        {
            DeviceDisplayName = "SanDisk Cruzer",
            CanSearchFileActivity = true,
            LinkKeys = ["буква диска E:"],
            Entries =
            [
                new DeviceActivityEntry
                {
                    TimestampUtc = new DateTimeOffset(2026, 3, 14, 10, 0, 0, TimeSpan.Zero),
                    Kind = DeviceActivityKind.FolderBrowse,
                    Path = @"E:\Фото\Отпуск",
                    LinkBasis = "Буква диска E:",
                    LinkConfidence = "Medium",
                    Source = "Live HKU SID_Classes Shellbags"
                }
            ],
            CopyIndications =
            [
                new CopyIndication
                {
                    FileName = "смета.xlsx",
                    PathOnDevice = @"E:\Отчёты\смета.xlsx",
                    LocalPath = @"C:\Users\ivanov\Documents\смета.xlsx"
                }
            ]
        };

        var failure = RunOnStaThread(() =>
        {
            var window = new DeviceActivityWindow(history);
            Assert.Equal(history.Entries, window.FindName("ActivityGrid") is System.Windows.Controls.DataGrid grid
                ? grid.ItemsSource
                : null);
            window.Close();
        });

        Assert.Null(failure);
    }

    [Fact]
    public void Device_details_window_opens_with_a_disabled_history_button_before_a_scan()
    {
        var failure = RunOnStaThread(() =>
        {
            var window = new DeviceDetailsWindow(new UsbDeviceRecord { FriendlyName = "SanDisk Cruzer" });
            Assert.False(((System.Windows.Controls.Button)window.FindName("ActivityButton")!).IsEnabled);
            window.Close();
        });

        Assert.Null(failure);
    }

    private static Exception? RunOnStaThread(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                _ = Application.Current ?? new Application();
                action();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join(TimeSpan.FromSeconds(30));
        return failure;
    }
}
