using System.Collections;
using System.ComponentModel;
using System.Globalization;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;

namespace UsbForensicAudit;

public sealed partial class DeviceDisplayGroup : ObservableObject
{
    [ObservableProperty] private string _title = "";
    public bool IsGrouped { get; init; }
    public int Order { get; init; }
    public IReadOnlyList<UsbDeviceRecord> Items { get; set; } = [];
    [ObservableProperty] private string _description = "";
    [ObservableProperty] private bool _isExpanded;
    [ObservableProperty] private bool? _isSelected = false;
}

public sealed class DevicePhysicalGrouping : GroupDescription
{
    private readonly Dictionary<UsbDeviceRecord, DeviceDisplayGroup> _items = [];
    private readonly Dictionary<object, DeviceDisplayGroup> _groups = [];
    private readonly DeviceDisplayGroup _other = new()
    {
        Title = "Отдельные записи",
        Description = "Другие записи этого устройства не найдены или связь не подтверждена"
    };

    public void SetExpanded(bool expanded)
    {
        foreach (var group in _groups.Values)
        {
            group.IsExpanded = expanded;
        }
    }

    public DevicePhysicalGrouping() => CustomSort = new GroupComparer();

    public void Clear()
    {
        _items.Clear();
        _groups.Clear();
    }

    public void UpdateSelection(IEnumerable<UsbDeviceRecord> selected)
    {
        var selection = selected.ToHashSet();
        foreach (var group in _items.Values.Distinct())
        {
            var count = group.Items.Count(selection.Contains);
            group.IsSelected = count == 0 ? false : count == group.Items.Count ? true : null;
        }
    }

    public static string? Pair(UsbDeviceRecord device)
    {
        var vid = device.Vid.Trim();
        var pid = device.Pid.Trim();
        return vid.Length == 4 && pid.Length == 4 && vid.All(Uri.IsHexDigit) && pid.All(Uri.IsHexDigit)
            ? $"VID {vid.ToUpperInvariant()} · PID {pid.ToUpperInvariant()}" : null;
    }

    public void Reset(IEnumerable<UsbDeviceRecord> visibleDevices, bool expandMatches = false)
    {
        _items.Clear();
        var other = new List<UsbDeviceRecord>();
        foreach (var physical in visibleDevices.GroupBy(DeviceListPresentation.GroupKey))
        {
            var members = physical.ToArray();
            if (members.Length < 2)
            {
                _items[members[0]] = _other;
                other.Add(members[0]);
                continue;
            }
            if (!_groups.TryGetValue(physical.Key, out var group))
            {
                _groups[physical.Key] = group = new DeviceDisplayGroup { IsGrouped = true, Order = _groups.Count };
            }
            var primary = members.FirstOrDefault(x => x.IsCanonicalPrimary) ?? members[0];
            group.Title = primary.DisplayName;
            group.Items = members;
            var serials = members.Select(x => x.Serial).Where(DeviceIdentityGraph.IsHardwareSerial)
                .Select(DeviceIdentityGraph.NormalizeSerial).Distinct(StringComparer.OrdinalIgnoreCase);
            var pairs = members.Select(Pair).Where(x => x is not null).Distinct();
            var details = new List<string> { $"Записей: {members.Length}" };
            var serial = string.Join(", ", serials);
            if (serial.Length > 0)
            {
                details.Add("S/N " + serial);
            }

            details.AddRange(pairs.Select(x => x!));
            if (serial.Length == 0 && !pairs.Any())
            {
                details.Add("Связь по идентификаторам Windows");
            }

            group.Description = string.Join("   ·   ", details);
            if (expandMatches)
            {
                group.IsExpanded = true;
            }
            foreach (var member in members)
            {
                _items[member] = group;
            }
        }
        _other.Items = other;
    }

    public override object GroupNameFromItem(object item, int level, CultureInfo culture)
    {
        if (item is not UsbDeviceRecord record)
        {
            return item;
        }

        if (!_items.TryGetValue(record, out var group))
        {
            _items[record] = group = new DeviceDisplayGroup { Order = _items.Count };
        }

        return group;
    }

    private sealed class GroupComparer : IComparer
    {
        public int Compare(object? x, object? y)
        {
            var a = (x as CollectionViewGroup)?.Name as DeviceDisplayGroup ?? x as DeviceDisplayGroup;
            var b = (y as CollectionViewGroup)?.Name as DeviceDisplayGroup ?? y as DeviceDisplayGroup;
            if (a is null || b is null)
            {
                return 0;
            }

            var rank = b.IsGrouped.CompareTo(a.IsGrouped);
            if (rank != 0)
            {
                return rank;
            }

            return a.Order.CompareTo(b.Order);
        }
    }
}
