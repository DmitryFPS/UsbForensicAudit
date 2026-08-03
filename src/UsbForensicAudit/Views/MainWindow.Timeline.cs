using System.Collections.Generic;
using System.Windows.Controls;
using System.Windows.Data;

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
        TimelineGrid.ItemsSource = _timelineView;
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

    private void TimelineFilter_Changed(object sender, SelectionChangedEventArgs e) => RefreshTimelineFilter();

    private void TimelineFilter_Changed(object sender, TextChangedEventArgs e) => RefreshTimelineFilter();

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
