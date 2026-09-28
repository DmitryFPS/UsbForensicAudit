using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Threading;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceGridScrollTests
{
    [Fact]
    public void Expanding_collapsing_and_bringing_groups_into_view_preserve_manual_horizontal_offset()
    {
        Exception? error = null;
        var thread = new Thread(() =>
        {
            try { Verify(); }
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

    private static void Verify()
    {
        var grid = new DataGrid { AutoGenerateColumns = false, IsReadOnly = true, SelectionMode = DataGridSelectionMode.Extended };
        DeviceGridScroll.SetIsEnabled(grid, true);
        for (var i = 0; i < 15; i++)
        {
            grid.Columns.Add(new DataGridTextColumn { Header = "Column " + i, Width = 180, Binding = new Binding("Name") });
        }

        var style = (GroupStyle)XamlReader.Parse("""
            <GroupStyle xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
              <GroupStyle.ContainerStyle><Style TargetType="GroupItem"><Setter Property="Template"><Setter.Value>
                <ControlTemplate TargetType="GroupItem"><StackPanel><ToggleButton x:Name="GroupToggle" Content="Device records" HorizontalContentAlignment="Stretch"/>
                  <ItemsPresenter x:Name="Rows"/></StackPanel>
                  <ControlTemplate.Triggers><Trigger SourceName="GroupToggle" Property="IsChecked" Value="False"><Setter TargetName="Rows" Property="Visibility" Value="Collapsed"/></Trigger></ControlTemplate.Triggers>
                </ControlTemplate>
              </Setter.Value></Setter></Style></GroupStyle.ContainerStyle>
            </GroupStyle>
            """);
        style.ContainerStyle.Setters.Add(new Setter(DeviceGridScroll.PreserveGroupViewportProperty, true));
        grid.GroupStyle.Add(style);
        var view = new ListCollectionView(Enumerable.Range(0, 8).Select(i => new Row("Device " + i, i / 2)).ToList());
        view.GroupDescriptions.Add(new PropertyGroupDescription("Group"));
        grid.ItemsSource = view;
        VirtualizingPanel.SetIsVirtualizingWhenGrouping(grid, true);
        var host = new Grid();
        host.Children.Add(grid);
        void Layout()
        {
            host.Measure(new Size(800, 400));
            host.Arrange(new Rect(0, 0, 800, 400));
            host.UpdateLayout();
            var frame = new DispatcherFrame();
            Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false));
            Dispatcher.PushFrame(frame);
            host.UpdateLayout();
        }
        Layout();
        Layout();
        var scroll = Descendants<ScrollViewer>(grid).First();
        var toggle = Descendants<ToggleButton>(grid).First(x => x.Name == "GroupToggle");
        Assert.True(scroll.ExtentWidth >= 2700);
        toggle.BringIntoView();
        toggle.IsChecked = true;
        Layout();
        Assert.Equal(0, scroll.HorizontalOffset);
        foreach (var offset in new[] { 200d, 600d })
        {
            scroll.ScrollToHorizontalOffset(offset);
            Layout();
            Assert.Equal(offset, scroll.HorizontalOffset);
            toggle.IsChecked = false;
            toggle.BringIntoView();
            Layout();
            Assert.Equal(offset, scroll.HorizontalOffset);
            toggle.IsChecked = true;
            toggle.BringIntoView();
            grid.SelectAll();
            Layout();
            Assert.Equal(offset, scroll.HorizontalOffset);
        }
        grid.Columns[0].Width = 240;
        Layout();
        Assert.Equal(2760, DeviceGridScroll.GetColumnsWidth(grid));
        DeviceGridScroll.SetIsEnabled(grid, false);
        foreach (var group in Descendants<GroupItem>(grid))
        {
            DeviceGridScroll.SetPreserveGroupViewport(group, false);
        }

        host.Children.Clear();
    }

    private sealed record Row(string Name, int Group);

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
}
