using System.Runtime.InteropServices;
using System.Windows.Automation;

namespace UsbForensicAudit;

internal static class Win32ListViewUiAutomationReader
{
    public static Win32ListViewReader.ListViewSnapshot Read(IntPtr listViewHandle)
    {
        GetWindowRect(listViewHandle, out var rect);
        var element = AutomationElement.FromHandle(listViewHandle);
        if (element == null)
        {
            return new Win32ListViewReader.ListViewSnapshot(listViewHandle, rect.Top, rect.Left, [], []);
        }

        if (TryReadViaTablePattern(element, listViewHandle, rect, out var tableSnapshot))
        {
            return tableSnapshot;
        }

        if (TryReadViaGridPattern(element, listViewHandle, rect, out var gridSnapshot))
        {
            return gridSnapshot;
        }

        return ReadViaListItems(element, listViewHandle, rect);
    }

    private static bool TryReadViaTablePattern(
        AutomationElement element,
        IntPtr listViewHandle,
        Rect rect,
        out Win32ListViewReader.ListViewSnapshot snapshot)
    {
        snapshot = null!;
        if (!element.TryGetCurrentPattern(TablePattern.Pattern, out var patternObject))
        {
            return false;
        }

        var table = (TablePattern)patternObject;
        var headers = table.Current.GetColumnHeaders()
            .Select(header => TextSanitizer.NormalizeDisplay(header.Current.Name, 200))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToArray();

        var rows = new List<IReadOnlyList<string>>();
        for (var rowIndex = 0; rowIndex < table.Current.RowCount; rowIndex++)
        {
            var cells = new List<string>();
            for (var columnIndex = 0; columnIndex < table.Current.ColumnCount; columnIndex++)
            {
                var cell = table.GetItem(rowIndex, columnIndex);
                cells.Add(TextSanitizer.NormalizeDisplay(cell.Current.Name, 500));
            }

            if (cells.Any(x => !string.IsNullOrWhiteSpace(x)))
            {
                rows.Add(cells);
            }
        }

        if (rows.Count == 0)
        {
            return false;
        }

        if (headers.Length == 0)
        {
            headers = BuildDefaultHeaders(rows.Max(x => x.Count));
        }

        snapshot = new Win32ListViewReader.ListViewSnapshot(listViewHandle, rect.Top, rect.Left, headers, rows);
        return true;
    }

    private static bool TryReadViaGridPattern(
        AutomationElement element,
        IntPtr listViewHandle,
        Rect rect,
        out Win32ListViewReader.ListViewSnapshot snapshot)
    {
        snapshot = null!;
        if (!element.TryGetCurrentPattern(GridPattern.Pattern, out var patternObject))
        {
            return false;
        }

        var grid = (GridPattern)patternObject;
        if (grid.Current.RowCount == 0 || grid.Current.ColumnCount == 0)
        {
            return false;
        }

        var headers = new List<string>();
        for (var columnIndex = 0; columnIndex < grid.Current.ColumnCount; columnIndex++)
        {
            headers.Add(TextSanitizer.NormalizeDisplay(grid.GetItem(0, columnIndex).Current.Name, 200));
        }

        var rows = new List<IReadOnlyList<string>>();
        var startRow = headers.All(string.IsNullOrWhiteSpace) ? 0 : 1;
        if (startRow == 0)
        {
            headers = BuildDefaultHeaders(grid.Current.ColumnCount).ToList();
        }

        for (var rowIndex = startRow; rowIndex < grid.Current.RowCount; rowIndex++)
        {
            var cells = new List<string>();
            for (var columnIndex = 0; columnIndex < grid.Current.ColumnCount; columnIndex++)
            {
                cells.Add(TextSanitizer.NormalizeDisplay(grid.GetItem(rowIndex, columnIndex).Current.Name, 500));
            }

            if (cells.Any(x => !string.IsNullOrWhiteSpace(x)))
            {
                rows.Add(cells);
            }
        }

        if (rows.Count == 0)
        {
            return false;
        }

        if (headers.Count == 0 || headers.All(string.IsNullOrWhiteSpace))
        {
            headers = BuildDefaultHeaders(rows.Max(x => x.Count)).ToList();
        }

        snapshot = new Win32ListViewReader.ListViewSnapshot(listViewHandle, rect.Top, rect.Left, headers, rows);
        return true;
    }

    private static Win32ListViewReader.ListViewSnapshot ReadViaListItems(
        AutomationElement element,
        IntPtr listViewHandle,
        Rect rect)
    {
        var headers = ReadHeaderItems(element);
        var items = element.FindAll(
            TreeScope.Children,
            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem));

        var rows = new List<IReadOnlyList<string>>();
        foreach (AutomationElement item in items)
        {
            var cells = ReadListItemCells(item);
            if (cells.Count == 0 || cells.All(string.IsNullOrWhiteSpace))
            {
                continue;
            }

            rows.Add(cells);
        }

        if (headers.Count == 0 && rows.Count > 0)
        {
            headers = BuildDefaultHeaders(rows.Max(x => x.Count)).ToList();
        }

        return new Win32ListViewReader.ListViewSnapshot(listViewHandle, rect.Top, rect.Left, headers, rows);
    }

    private static List<string> ReadHeaderItems(AutomationElement listView)
    {
        var parent = TreeWalker.ControlViewWalker.GetParent(listView);
        if (parent == null)
        {
            return [];
        }

        var headerItems = parent.FindAll(
            TreeScope.Descendants,
            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.HeaderItem));

        if (headerItems.Count == 0)
        {
            return [];
        }

        return headerItems
            .Cast<AutomationElement>()
            .OrderBy(x => x.Current.BoundingRectangle.Left)
            .Select(x => TextSanitizer.NormalizeDisplay(x.Current.Name, 200))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToList();
    }

    private static List<string> ReadListItemCells(AutomationElement item)
    {
        var textChildren = item.FindAll(
            TreeScope.Descendants,
            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text));
        if (textChildren.Count > 0)
        {
            return textChildren
                .Cast<AutomationElement>()
                .OrderBy(x => x.Current.BoundingRectangle.Left)
                .Select(ReadElementText)
                .ToList();
        }

        var children = item.FindAll(TreeScope.Children, Condition.TrueCondition);
        if (children.Count > 0)
        {
            return children
                .Cast<AutomationElement>()
                .OrderBy(x => x.Current.BoundingRectangle.Left)
                .Select(ReadElementText)
                .ToList();
        }

        var name = ReadElementText(item);
        if (name.Contains('\t', StringComparison.Ordinal))
        {
            return name.Split('\t').Select(x => TextSanitizer.NormalizeDisplay(x, 500)).ToList();
        }

        if (item.TryGetCurrentPattern(ValuePattern.Pattern, out var valuePatternObject))
        {
            var value = TextSanitizer.NormalizeDisplay(((ValuePattern)valuePatternObject).Current.Value, 500);
            if (!string.IsNullOrWhiteSpace(value) && !value.Equals(name, StringComparison.Ordinal))
            {
                return [name, value];
            }
        }

        return string.IsNullOrWhiteSpace(name) ? [] : [name];
    }

    private static string ReadElementText(AutomationElement element)
    {
        if (element.TryGetCurrentPattern(ValuePattern.Pattern, out var valuePatternObject))
        {
            var value = ((ValuePattern)valuePatternObject).Current.Value;
            if (!string.IsNullOrWhiteSpace(value))
            {
                return TextSanitizer.NormalizeDisplay(value, 500);
            }
        }

        return TextSanitizer.NormalizeDisplay(element.Current.Name, 500);
    }

    private static string[] BuildDefaultHeaders(int columnCount) =>
        Enumerable.Range(0, columnCount).Select(index => $"Колонка {index + 1}").ToArray();

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hWnd, out Rect lpRect);
}
