using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class DeviceSelectionTests
{
    [Fact]
    public void Checkbox_mouse_clicks_toggle_once_and_preserve_other_selected_rows()
    {
        OnSta(() =>
        {
            var grid = CreateGrid();
            var boxes = Descendants<DeviceSelectionCheckBox>(grid).ToArray();
            Assert.Equal(3, boxes.Length);
            Click(boxes[0]);
            Assert.True(boxes[0].IsChecked);
            Assert.Single(grid.SelectedItems);
            Click(boxes[1]);
            Assert.True(boxes[0].IsChecked);
            Assert.True(boxes[1].IsChecked);
            Assert.Equal(2, grid.SelectedItems.Count);
            Click(boxes[2]);
            Assert.Equal(3, grid.SelectedItems.Count);
            Click(boxes[1]);
            Assert.False(boxes[1].IsChecked);
            Assert.True(boxes[0].IsChecked);
            Assert.True(boxes[2].IsChecked);
            Assert.Equal(2, grid.SelectedItems.Count);
            grid.UnselectAll();
            Assert.All(boxes, box => Assert.False(box.IsChecked));
            grid.SelectAll();
            Assert.All(boxes, box => Assert.True(box.IsChecked));
        });
    }

    [Fact]
    public void Accessible_toggle_preserves_multiple_selection_and_binding()
    {
        OnSta(() =>
        {
            var grid = CreateGrid();
            var boxes = Descendants<DeviceSelectionCheckBox>(grid).ToArray();
            foreach (var box in boxes)
            {
                var peer = new CheckBoxAutomationPeer(box);
                ((IToggleProvider)peer.GetPattern(PatternInterface.Toggle)).Toggle();
            }
            Assert.Equal(3, grid.SelectedItems.Count);
            grid.UnselectAll();
            Assert.All(boxes, box => Assert.False(box.IsChecked));
            Click(boxes[0]);
            Assert.True(boxes[0].IsChecked);
            Assert.Single(grid.SelectedItems);
            new DeviceSelectionCheckBox().RaiseEvent(new MouseButtonEventArgs(Mouse.PrimaryDevice, 0, MouseButton.Left)
            {
                RoutedEvent = UIElement.PreviewMouseLeftButtonDownEvent
            });
        });
    }

    private static DataGrid CreateGrid()
    {
        _ = Application.Current ?? new Application();
        var grid = new DataGrid
        {
            SelectionMode = DataGridSelectionMode.Extended,
            SelectionUnit = DataGridSelectionUnit.FullRow,
            AutoGenerateColumns = false,
            CanUserAddRows = false,
            EnableColumnVirtualization = false,
            EnableRowVirtualization = false,
            IsReadOnly = true,
            ItemsSource = new[] { new UsbDeviceRecord(), new UsbDeviceRecord(), new UsbDeviceRecord() }
        };
        grid.Columns.Add(new DataGridTemplateColumn
        {
            Width = 80,
            CellTemplate = new DataTemplate { VisualTree = new FrameworkElementFactory(typeof(DeviceSelectionCheckBox)) }
        });
        var host = new Window { Content = grid };
        grid.Measure(new Size(600, 400));
        grid.Arrange(new Rect(0, 0, 600, 400));
        grid.UpdateLayout();
        Assert.Equal(3, Descendants<DeviceSelectionCheckBox>(grid).Count());
        host.Content = null;
        host.Close();
        return grid;
    }

    private static void Click(DeviceSelectionCheckBox box)
    {
        // Проходим маршрут Preview и проверяем, что таблица и ToggleButton не получат второй щелчок.
        foreach (var routedEvent in new[] { Mouse.PreviewMouseDownEvent, Mouse.PreviewMouseUpEvent })
        {
            var args = new MouseButtonEventArgs(Mouse.PrimaryDevice, 0, MouseButton.Left) { RoutedEvent = routedEvent };
            box.RaiseEvent(args);
            Assert.True(args.Handled);
        }
    }

    private static IEnumerable<T> Descendants<T>(DependencyObject root) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T match)
            {
                yield return match;
            }

            foreach (var nested in Descendants<T>(child))
            {
                yield return nested;
            }
        }
    }

    private static void OnSta(Action action)
    {
        Exception? error = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception ex) { error = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(15)));
        if (error is not null)
        {
            ExceptionDispatchInfo.Capture(error).Throw();
        }
    }
}
