using System;
using System.Collections.Generic;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;

namespace UsbForensicAudit;

/// <summary>
/// Вкладка «Таймлайн»: единая лента событий поверх TimelineViewBuilder с
/// фильтрами по типу, устройству и тексту. Логика сборки и предикат
/// фильтрации живут в Application и покрыты тестами; здесь — только привязка.
/// </summary>
public partial class MainWindow
{
    private const string TimelineAllKinds = "Все события";
    private const string TimelineAllDevices = "Все устройства";

    private IReadOnlyList<TimelineViewEntry> _timelineEntries = [];
    private ListCollectionView? _timelineView;

    private void RefreshTimeline(AuditResult result)
    {
        _timelineEntries = TimelineViewBuilder.Build(result);

        TimelineKindCombo.Items.Clear();
        TimelineKindCombo.Items.Add(TimelineAllKinds);
        foreach (var kind in TimelineViewBuilder.Kinds)
        {
            TimelineKindCombo.Items.Add(kind);
        }

        TimelineKindCombo.SelectedIndex = 0;

        TimelineDeviceCombo.Items.Clear();
        TimelineDeviceCombo.Items.Add(TimelineAllDevices);
        foreach (var device in TimelineViewBuilder.Devices(_timelineEntries))
        {
            TimelineDeviceCombo.Items.Add(device);
        }

        TimelineDeviceCombo.SelectedIndex = 0;
        TimelineSearchBox.Text = "";

        _timelineView = new ListCollectionView((System.Collections.IList)_timelineEntries)
        {
            Filter = TimelineFilterPredicate
        };
        // Лента группируется по дням: заголовок «1 мая 2026» перед событиями дня.
        _timelineView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(TimelineViewEntry.DayText)));
        TimelineGrid.ItemsSource = _timelineView;
        // Как и остальные таблицы: без отложенной подгонки DataGrid, заполненный
        // на невидимой вкладке, рисует столбцы минимальной ширины — «слипшимися».
        DataGridAutoSize.FitColumns(TimelineGrid);
        UpdateTimelineCount();
    }

    private bool TimelineFilterPredicate(object item)
    {
        if (item is not TimelineViewEntry entry)
        {
            return false;
        }

        var kind = TimelineKindCombo.SelectedItem as string;
        var device = TimelineDeviceCombo.SelectedItem as string;
        return TimelineViewBuilder.Matches(
            entry,
            kind is null or TimelineAllKinds ? null : kind,
            device is null or TimelineAllDevices ? null : device,
            TimelineSearchBox.Text);
    }

    private DispatcherTimer? _timelineFilterDebounce;

    // Выбор в списках применяем сразу — событий немного.
    private void TimelineFilter_Changed(object sender, SelectionChangedEventArgs e) => RefreshTimelineFilter();

    // Ввод текста поиска — с задержкой: полный проход по всей ленте на каждую
    // букву давал заметный лаг на большой истории. Перезапускаемый таймер
    // применяет фильтр один раз после паузы в наборе.
    private void TimelineFilter_Changed(object sender, TextChangedEventArgs e)
    {
        _timelineFilterDebounce ??= CreateTimelineDebounceTimer();
        _timelineFilterDebounce.Stop();
        _timelineFilterDebounce.Start();
    }

    private DispatcherTimer CreateTimelineDebounceTimer()
    {
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(180) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            RefreshTimelineFilter();
        };
        return timer;
    }

    private void RefreshTimelineFilter()
    {
        if (_timelineView is null)
        {
            return;
        }

        _timelineView.Refresh();
        UpdateTimelineCount();
    }

    private void UpdateTimelineCount() =>
        TimelineCountText.Text = _timelineView is null
            ? ""
            : $"Показано событий: {_timelineView.Count} из {_timelineEntries.Count}";
}
