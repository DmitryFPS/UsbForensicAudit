using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace UsbForensicAudit;

/// <summary>Сохраняет горизонтальную область таблицы при раскрытии и выборе групп.</summary>
public static class DeviceGridScroll
{
    public static readonly DependencyProperty IsEnabledProperty = DependencyProperty.RegisterAttached(
        "IsEnabled", typeof(bool), typeof(DeviceGridScroll), new PropertyMetadata(false, OnEnabledChanged));

    public static readonly DependencyProperty PreserveGroupViewportProperty = DependencyProperty.RegisterAttached(
        "PreserveGroupViewport", typeof(bool), typeof(DeviceGridScroll), new PropertyMetadata(false, OnGroupChanged));

    private static readonly DependencyPropertyKey ColumnsWidthPropertyKey = DependencyProperty.RegisterAttachedReadOnly(
        "ColumnsWidth", typeof(double), typeof(DeviceGridScroll), new PropertyMetadata(0d));

    public static readonly DependencyProperty ColumnsWidthProperty = ColumnsWidthPropertyKey.DependencyProperty;

    private static readonly DependencyProperty KeyboardNavigationProperty = DependencyProperty.RegisterAttached(
        "KeyboardNavigation", typeof(bool), typeof(DeviceGridScroll), new PropertyMetadata(false));

    private static readonly DependencyProperty LayoutHandlerProperty = DependencyProperty.RegisterAttached("LayoutHandler", typeof(EventHandler), typeof(DeviceGridScroll));

    public static bool GetIsEnabled(DependencyObject element) => (bool)element.GetValue(IsEnabledProperty);
    public static void SetIsEnabled(DependencyObject element, bool value) => element.SetValue(IsEnabledProperty, value);
    public static bool GetPreserveGroupViewport(DependencyObject element) => (bool)element.GetValue(PreserveGroupViewportProperty);
    public static void SetPreserveGroupViewport(DependencyObject element, bool value) => element.SetValue(PreserveGroupViewportProperty, value);
    public static double GetColumnsWidth(DependencyObject element) => (double)element.GetValue(ColumnsWidthProperty);

    private static void OnEnabledChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not DataGrid grid)
        {
            return;
        }

        if ((bool)e.NewValue)
        {
            EventHandler handler = (_, _) => UpdateColumnsWidth(grid);
            grid.SetValue(LayoutHandlerProperty, handler);
            grid.LayoutUpdated += handler;
            grid.PreviewKeyDown += OnPreviewKeyDown;
        }
        else
        {
            grid.LayoutUpdated -= (EventHandler)grid.GetValue(LayoutHandlerProperty);
            grid.ClearValue(LayoutHandlerProperty);
            grid.PreviewKeyDown -= OnPreviewKeyDown;
            grid.ClearValue(ColumnsWidthPropertyKey);
            grid.ClearValue(KeyboardNavigationProperty);
        }
    }

    private static void UpdateColumnsWidth(DataGrid grid)
    {
        // При свёрнутых группах WPF измеряет только короткие заголовки. Без этой
        // ширины ScrollViewer уменьшает extent и обнуляет выбранную пользователем позицию.
        var width = grid.Columns.Where(column => column.Visibility == Visibility.Visible).Sum(column => column.ActualWidth);
        if (Math.Abs(GetColumnsWidth(grid) - width) > 0.01)
        {
            grid.SetValue(ColumnsWidthPropertyKey, width);
        }
    }

    private static void OnGroupChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not GroupItem group)
        {
            return;
        }

        if ((bool)e.NewValue)
        {
            group.SetBinding(FrameworkElement.MinWidthProperty, new Binding
            {
                RelativeSource = new RelativeSource(RelativeSourceMode.FindAncestor, typeof(DataGrid), 1),
                Path = new PropertyPath("(0)", ColumnsWidthProperty)
            });
            group.RequestBringIntoView += OnRequestBringIntoView;
        }
        else
        {
            BindingOperations.ClearBinding(group, FrameworkElement.MinWidthProperty);
            group.RequestBringIntoView -= OnRequestBringIntoView;
        }
    }

    private static void OnRequestBringIntoView(object sender, RequestBringIntoViewEventArgs e)
    {
        for (DependencyObject? current = (GroupItem)sender; current is not null; current = VisualTreeHelper.GetParent(current))
        {
            if (current is not DataGrid grid)
            {
                continue;
            }

            // Щелчок по широкому заголовку или строке не должен подтягивать его
            // правый край. Явная навигация клавиатурой продолжает открывать нужную ячейку.
            if (GetIsEnabled(grid) && !(bool)grid.GetValue(KeyboardNavigationProperty))
            {
                e.Handled = true;
            }
            return;
        }
    }

    private static void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key is not (Key.Left or Key.Right or Key.Up or Key.Down or Key.Home or Key.End or Key.PageUp or Key.PageDown or Key.Tab))
        {
            return;
        }

        var grid = (DataGrid)sender;
        if ((bool)grid.GetValue(KeyboardNavigationProperty))
        {
            return;
        }
        grid.SetValue(KeyboardNavigationProperty, true);
        grid.Dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(() => grid.ClearValue(KeyboardNavigationProperty)));
    }
}


