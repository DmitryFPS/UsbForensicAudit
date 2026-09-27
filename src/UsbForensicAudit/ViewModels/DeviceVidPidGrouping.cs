using System.Collections;
using System.ComponentModel;
using System.Globalization;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;

namespace UsbForensicAudit;

public sealed partial class DeviceDisplayGroup : ObservableObject
{
    public string Title { get; init; } = "";
    public bool IsGrouped { get; init; }
    public int Order { get; init; }
    [ObservableProperty] private string _description = "";
    [ObservableProperty] private bool _isExpanded = true;
}

public sealed class DeviceVidPidGrouping : GroupDescription
{
    private readonly Dictionary<UsbDeviceRecord, DeviceDisplayGroup> _items = [];
    private Dictionary<string, DeviceDisplayGroup> _groups = [];
    private readonly DeviceDisplayGroup _other = new()
    {
        Title = "Другие записи",
        Description = "Одиночные VID/PID и записи без этих кодов"
    };

    public void SetExpanded(bool expanded)
    {
        foreach (var group in _groups.Values)
        {
            group.IsExpanded = expanded;
        }
    }

    public DeviceVidPidGrouping() => CustomSort = new GroupComparer();

    public static string? Pair(UsbDeviceRecord device)
    {
        var vid = device.Vid.Trim();
        var pid = device.Pid.Trim();
        return vid.Length == 4 && pid.Length == 4 && vid.All(Uri.IsHexDigit) && pid.All(Uri.IsHexDigit)
            ? $"VID {vid.ToUpperInvariant()} · PID {pid.ToUpperInvariant()}" : null;
    }

    public void Reset(IEnumerable<UsbDeviceRecord> visibleDevices, bool expandMatches = false)
    {
        var devices = visibleDevices.ToArray();
        var previous = _groups;
        _groups = devices.Select(Pair).Where(x => x is not null).GroupBy(x => x!)
            .Where(x => x.Count() > 1)
            .ToDictionary(x => x.Key, x => previous.GetValueOrDefault(x.Key)
                ?? new DeviceDisplayGroup { Title = x.Key, IsGrouped = true });
        _items.Clear();
        foreach (var pair in _groups)
        {
            var names = devices.Where(x => Pair(x) == pair.Key).Select(x => x.DisplayName)
                .Distinct(StringComparer.OrdinalIgnoreCase).Take(2);
            pair.Value.Description = string.Join(" / ", names);
        }
        for (var i = 0; i < devices.Length; i++)
        {
            var pair = Pair(devices[i]);
            _items[devices[i]] = pair is not null && _groups.TryGetValue(pair, out var group)
                ? group : _other;
        }
        if (expandMatches)
        {
            foreach (var group in _groups.Values)
            {
                group.IsExpanded = true;
            }
        }
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

            return a.IsGrouped ? StringComparer.Ordinal.Compare(a.Title, b.Title) : a.Order.CompareTo(b.Order);
        }
    }
}
