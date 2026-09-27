using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace UsbForensicAudit;

/// <summary>Один щелчок переключает строку один раз и сохраняет остальные отмеченные строки.</summary>
public sealed class DeviceSelectionCheckBox : CheckBox
{
    public DeviceSelectionCheckBox()
    {
        SetBinding(IsCheckedProperty, new Binding(nameof(DataGridRow.IsSelected))
        {
            RelativeSource = new RelativeSource(RelativeSourceMode.FindAncestor, typeof(DataGridRow), 1),
            Mode = BindingMode.OneWay
        });
    }

    protected override void OnPreviewMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        // Не передаём нажатие DataGridCell: иначе таблица сначала выбирает строку,
        // а стандартный ToggleButton тут же снимает её выбор.
        e.Handled = true;
        OnToggle();
    }

    protected override void OnPreviewMouseLeftButtonUp(MouseButtonEventArgs e) => e.Handled = true;

    protected override void OnToggle()
    {
        for (DependencyObject? current = this; current is not null; current = VisualTreeHelper.GetParent(current))
        {
            if (current is DataGridRow row)
            {
                row.IsSelected = !row.IsSelected;
                return;
            }
        }
    }
}
