using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Windows.Data;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceGroupingAndConnectionTests
{
    [Fact]
    public void Preview_separates_removable_records_from_protected_records()
    {
        OnSta(() =>
        {
            var plan = new DeviceRemovalPlan("TEST", "test", DateTimeOffset.UtcNow,
                [new("A", "Allowed", true, "", null, []), new("B", "Blocked", false, "Connected", null, [])]);
            var window = new DeviceRemovalPreviewWindow(plan);
            var grid = (System.Windows.Controls.DataGrid)window.FindName("PlanGrid");
            Assert.Equal(2, grid.Items.Count);
            Assert.True(((DeviceRemovalItem)grid.Items[0]).CanRemove);
            Assert.Contains("частичной", ((System.Windows.Controls.TextBlock)window.FindName("SummaryText")).Text);
            ((System.Windows.Controls.CheckBox)window.FindName("ShowProtected")).IsChecked = false;
            Assert.Single(grid.Items);
            window.Close();
        });
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Preview_window_only_enables_removal_when_the_plan_has_eligible_instances(bool canRemove)
    {
        OnSta(() =>
        {
            const string id = @"USB\VID_1234&PID_5678\SERIAL";
            var plan = new DeviceRemovalPlan("TEST", "test", DateTimeOffset.UtcNow,
                [new(id, "Test", canRemove, canRemove ? "" : "Подключено", new(id, "Test", !canRemove), [id])]);
            var window = new DeviceRemovalPreviewWindow(plan);
            Assert.Equal(plan.Items, ((System.Windows.Controls.DataGrid)window.FindName("PlanGrid")).ItemsSource);
            Assert.Equal(canRemove, ((System.Windows.Controls.Button)window.FindName("RemoveButton")).IsEnabled);
            window.Close();
        });
    }

    [Fact]
    public void Same_model_or_reused_drive_letter_does_not_mark_another_instance_connected()
    {
        var index = ConnectedDeviceIndex.Build([@"USB\VID_1234&PID_5678\SERIAL-A"], ["E:"]);
        Assert.False(index.IsConnected(new()
        {
            DeviceInstanceId = @"USB\VID_1234&PID_5678\SERIAL-B",
            Vid = "1234",
            Pid = "5678",
            Serial = "SERIAL-B",
            DriveLetters = "E:"
        }));
        Assert.False(index.IsConnected(new()
        {
            DeviceInstanceId = @"USB\VID_ABCD&PID_1234\SERIAL-A",
            Vid = "ABCD",
            Pid = "1234",
            Serial = "SERIAL-A"
        }));
        Assert.True(index.IsConnected(new() { DeviceInstanceId = @"usb\vid_1234&pid_5678\serial-a" }));
    }

    [Fact]
    public void Wpd_backing_instance_and_explicit_group_link_preserve_proven_connection()
    {
        const string id = @"USBSTOR\Disk&Ven_Test\SERIAL123&0";
        var index = ConnectedDeviceIndex.Build([id], []);
        Assert.True(index.IsConnected(new() { DeviceInstanceId = @"SWD\WPDBUSENUM\WRAPPER", IdentityAliases = [id] }));
        Assert.True(index.IsConnected(new() { DeviceInstanceId = @"USB\VID_1234&PID_5678\SERIAL123", LinkedSourceIds = [id] }));
        Assert.True(ConnectedDeviceIndex.Empty.IsConnected(new() { IsCurrentlyConnected = true }));
        Assert.False(ConnectedDeviceIndex.Empty.IsConnected(new()));
    }

    [Theory]
    [InlineData("12", "5678")]
    [InlineData("1234", "")]
    [InlineData("ZZZZ", "1234")]
    public void Incomplete_or_invalid_pairs_are_not_group_keys(string vid, string pid) =>
        Assert.Null(DevicePhysicalGrouping.Pair(new() { Vid = vid, Pid = pid }));

    [Fact]
    public void Physical_groups_include_missing_pairs_and_precede_independent_records_in_the_wpf_view()
    {
        OnSta(() =>
        {
            var missing = new UsbDeviceRecord { FriendlyName = "Без VID/PID" };
            var single = new UsbDeviceRecord { Vid = "0001", Pid = "0002" };
            var first = new UsbDeviceRecord { FriendlyName = "Накопитель", CanonicalDeviceId = "ONE", IsCanonicalPrimary = true, Vid = "abcd", Pid = "1234", Serial = "SERIAL-ONE" };
            var second = new UsbDeviceRecord { FriendlyName = "Другая запись", CanonicalDeviceId = "one", Serial = "SERIAL-ONE" };
            var list = new List<UsbDeviceRecord> { missing, single, first, second };
            var grouping = new DevicePhysicalGrouping();
            grouping.Reset(list);
            var view = new ListCollectionView(list);
            view.GroupDescriptions.Add(grouping);
            var groups = view.Groups!.Cast<CollectionViewGroup>().ToArray();
            Assert.Equal(2, groups.Length);
            Assert.True(((DeviceDisplayGroup)groups[0].Name).IsGrouped);
            Assert.Equal("Накопитель", ((DeviceDisplayGroup)groups[0].Name).Title);
            Assert.Contains("VID ABCD · PID 1234", ((DeviceDisplayGroup)groups[0].Name).Description);
            Assert.Contains("S/N SERIAL-ONE", ((DeviceDisplayGroup)groups[0].Name).Description);
            Assert.Equal(2, groups[0].ItemCount);
            Assert.Equal("Отдельные записи", ((DeviceDisplayGroup)groups[1].Name).Title);
            Assert.Equal(2, groups[1].ItemCount);
            Assert.Equal([first, second, missing, single], view.Cast<UsbDeviceRecord>());
            var deviceGroup = (DeviceDisplayGroup)groups[0].Name;
            Assert.False(deviceGroup.IsExpanded);
            grouping.UpdateSelection([first]);
            Assert.Null(deviceGroup.IsSelected);
            grouping.UpdateSelection([first, second]);
            Assert.True(deviceGroup.IsSelected);
            grouping.UpdateSelection([]);
            Assert.False(deviceGroup.IsSelected);

            ((DeviceDisplayGroup)groups[0].Name).IsExpanded = false;
            grouping.Reset(list);
            view.Refresh();
            Assert.False(((DeviceDisplayGroup)((CollectionViewGroup)view.Groups![0]).Name).IsExpanded);
            grouping.Reset(list, expandMatches: true);
            view.Refresh();
            Assert.True(((DeviceDisplayGroup)((CollectionViewGroup)view.Groups![0]).Name).IsExpanded);
            grouping.SetExpanded(false);
            Assert.False(((DeviceDisplayGroup)((CollectionViewGroup)view.Groups![0]).Name).IsExpanded);
            grouping.SetExpanded(true);
            Assert.True(((DeviceDisplayGroup)((CollectionViewGroup)view.Groups![0]).Name).IsExpanded);

            // После фильтрации оставшаяся одиночная запись теряет групповой заголовок.
            view.Filter = x => !ReferenceEquals(x, second);
            grouping.Reset(list.Where(x => !ReferenceEquals(x, second)));
            view.Refresh();
            Assert.All(view.Groups!.Cast<CollectionViewGroup>(), g => Assert.False(((DeviceDisplayGroup)g.Name).IsGrouped));
            Assert.Equal(3, view.Cast<UsbDeviceRecord>().Count());
            grouping.Clear();
            grouping.Reset(list);
            view.Filter = null;
            view.Refresh();
            Assert.False(((DeviceDisplayGroup)((CollectionViewGroup)view.Groups![0]).Name).IsExpanded);
        });
    }

    [Fact]
    public void Identical_vid_pid_never_combines_two_physical_devices()
    {
        var first = new UsbDeviceRecord { CanonicalDeviceId = "ONE", Vid = "0951", Pid = "1666" };
        var second = new UsbDeviceRecord { CanonicalDeviceId = "TWO", Vid = "0951", Pid = "1666" };
        var a = new UsbDeviceRecord { CanonicalDeviceId = "ONE" };
        var b = new UsbDeviceRecord { CanonicalDeviceId = "TWO" };
        var grouping = new DevicePhysicalGrouping();
        grouping.Reset([first, a, second, b]);
        var one = grouping.GroupNameFromItem(first, 0, CultureInfo.InvariantCulture);
        var two = grouping.GroupNameFromItem(second, 0, CultureInfo.InvariantCulture);
        Assert.NotSame(one, two);
        Assert.Same(one, grouping.GroupNameFromItem(a, 0, CultureInfo.InvariantCulture));
        Assert.Same(two, grouping.GroupNameFromItem(b, 0, CultureInfo.InvariantCulture));
    }

    [Theory]
    [InlineData("1234 SERIAL", true)]
    [InlineData("флешка", true)]
    [InlineData("SERIAL missing", false)]
    [InlineData("  ", true)]
    public void Device_search_uses_all_tokens_without_changing_source_records(string query, bool expected)
    {
        var device = new UsbDeviceRecord
        {
            FriendlyName = "Тестовая флешка",
            Vid = "1234",
            Pid = "ABCD",
            Serial = "SERIAL-123",
            DeviceInstanceId = @"USB\VID_1234&PID_ABCD\SERIAL-123"
        };
        Assert.Equal(expected, DeviceSearch.Matches(device, query));
        Assert.Equal("SERIAL-123", device.Serial);
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
