using System.Diagnostics.CodeAnalysis;
using System.ComponentModel;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace UsbForensicAudit;

/// <summary>
/// Показывает, что делали на конкретном устройстве: какие папки открывали, какие
/// файлы открывали и удаляли, что запускали. У каждой строки видно основание,
/// по которому она отнесена к этому устройству, — иначе список нечем проверить.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "WPF-окно")]
public partial class DeviceActivityWindow : Window
{
    private const string AllKinds = "Все действия";

    private readonly DeviceActivityHistory _history;
    private readonly ICollectionView _view;

    public DeviceActivityWindow(DeviceActivityHistory history)
    {
        InitializeComponent();
        _history = history;
        DarkWindowChrome.Apply(this);

        TitleText.Text = $"История действий: {history.DeviceDisplayName}";
        VerdictText.Text = history.Verdict();
        CopyVerdictText.Text = history.CopyVerdict();
        LinkKeysText.Text = DescribeLinkKeys(history);

        if (history.Entries.Count >= DeviceActivityBuilder.MaxEntries)
        {
            WarningText.Text = $"Показаны последние {DeviceActivityBuilder.MaxEntries} действий: "
                               + "следов больше, чем помещается в окно. Полный перечень — в отчёте.";
            WarningText.Visibility = Visibility.Visible;
        }

        ActivityGrid.ItemsSource = history.Entries;
        CopyGrid.ItemsSource = history.CopyIndications;
        _view = CollectionViewSource.GetDefaultView(ActivityGrid.ItemsSource);
        _view.Filter = FilterByKind;

        FillKindFilter(history);
        UpdateCount();
    }

    private void FillKindFilter(DeviceActivityHistory history)
    {
        KindFilterCombo.Items.Add(AllKinds);
        foreach (var kind in history.Entries
                     .Select(x => x.Kind)
                     .Distinct()
                     .OrderBy(DeviceActivityKind.Rank))
        {
            KindFilterCombo.Items.Add(DeviceActivityKind.Describe(kind));
        }

        KindFilterCombo.SelectedIndex = 0;
    }

    private bool FilterByKind(object item)
    {
        if (item is not DeviceActivityEntry entry)
        {
            return false;
        }

        var selected = KindFilterCombo.SelectedItem as string ?? AllKinds;
        return selected == AllKinds || entry.KindText == selected;
    }

    private void KindFilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _view.Refresh();
        UpdateCount();
    }

    private void UpdateCount()
    {
        var shown = _view.Cast<object>().Count();
        CountText.Text = shown == _history.Entries.Count
            ? $"Записей: {shown}"
            : $"Записей: {shown} из {_history.Entries.Count}";
    }

    private static string DescribeLinkKeys(DeviceActivityHistory history)
    {
        if (history.LinkKeys.Count == 0)
        {
            return "У этого устройства нет признаков, по которым можно связать след пользовательской "
                   + "активности с ним самим. Проводник запоминает путь вида «E:\\Папка», а не серийный "
                   + "номер носителя, поэтому без буквы диска, серийного номера тома или GUID тома "
                   + "искать не по чему.";
        }

        var builder = new StringBuilder();
        builder.AppendLine("Следы искались по этим признакам устройства:");
        builder.AppendLine();
        foreach (var key in history.LinkKeys)
        {
            builder.AppendLine($"  • {key}");
        }

        builder.AppendLine();
        builder.AppendLine("Серийный номер тома и GUID тома уникальны, поэтому привязка по ним надёжна.");
        builder.AppendLine("Буква диска не уникальна: Windows выдаёт первую свободную, и за год одна и та же");
        builder.AppendLine("буква достаётся разным носителям. Если буква встречалась у нескольких устройств,");
        builder.AppendLine("привязка по ней помечена как предположение.");
        return builder.ToString();
    }

    private void CopyButton_Click(object sender, RoutedEventArgs e)
    {
        var text = new StringBuilder();
        text.AppendLine($"История действий: {_history.DeviceDisplayName}");
        text.AppendLine(_history.Verdict());
        text.AppendLine();
        foreach (var entry in _history.Entries)
        {
            text.AppendLine($"{entry.TimestampText}\t{entry.KindText}\t{entry.Path}\t{entry.UserText}"
                            + $"\t{entry.LinkText}\t{entry.SourceText}");
        }

        text.AppendLine();
        text.AppendLine(_history.CopyVerdict());
        foreach (var indication in _history.CopyIndications)
        {
            text.AppendLine($"{indication.FileName}\t{indication.DirectionText}\t{indication.ConfidenceText}"
                            + $"\t{indication.GapText}\t{indication.PathOnDevice}\t{indication.SeenOnDeviceText}"
                            + $"\t{indication.LocalPath}\t{indication.SeenLocallyText}\t{indication.Basis}");
        }

        try
        {
            Clipboard.SetText(text.ToString());
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Не удалось скопировать в буфер: {ex.Message}", "История действий",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
