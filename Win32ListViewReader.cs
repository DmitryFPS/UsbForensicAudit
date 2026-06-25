using System.Runtime.InteropServices;
using System.Text;

namespace UsbForensicAudit;

internal static class Win32ListViewReader
{
    private const int LvmFirst = 0x1000;
    private const int LvmGetItemCount = LvmFirst + 4;
    private const int LvmGetItemTextW = LvmFirst + 115;
    private const int LvmGetHeader = LvmFirst + 31;

    private const int HdmFirst = 0x1200;
    private const int HdmGetItemCount = HdmFirst;
    private const int HdmGetItemW = HdmFirst + 11;

    private const int LvifText = 0x0001;
    private const int HdiText = 0x0002;

    public sealed record ListViewSnapshot(
        IntPtr Handle,
        int Top,
        int Left,
        IReadOnlyList<string> Headers,
        IReadOnlyList<IReadOnlyList<string>> Rows);

    public static ListViewSnapshot Read(IntPtr listViewHandle, int ownerProcessId, IntPtr? mainWindowHandle = null, string? utilityId = null)
    {
        var uiAutomationSnapshot = Win32ListViewUiAutomationReader.Read(listViewHandle);
        if (IsSnapshotUsable(uiAutomationSnapshot, requireMultipleColumns: true)
            && !IsSnapshotMisaligned(uiAutomationSnapshot))
        {
            return uiAutomationSnapshot;
        }

        if (mainWindowHandle is IntPtr mainWindow && mainWindow != IntPtr.Zero)
        {
            var clipboardSnapshot = Win32ListViewClipboardReader.TryRead(mainWindow, listViewHandle);
            if (clipboardSnapshot is not null
                && IsSnapshotUsable(clipboardSnapshot, requireMultipleColumns: false)
                && !IsSnapshotMisaligned(clipboardSnapshot))
            {
                return clipboardSnapshot;
            }
        }

        if (!ProcessBitnessHelper.RequiresUiAutomationForWindowMessages(ownerProcessId))
        {
            var directSnapshot = ReadDirect(listViewHandle);
            if (IsSnapshotUsable(directSnapshot, requireMultipleColumns: false)
                && !IsSnapshotMisaligned(directSnapshot))
            {
                return directSnapshot;
            }
        }

        if (mainWindowHandle is IntPtr retryWindow && retryWindow != IntPtr.Zero)
        {
            var clipboardSnapshot = Win32ListViewClipboardReader.TryRead(retryWindow, listViewHandle);
            if (clipboardSnapshot is not null && IsSnapshotUsable(clipboardSnapshot, requireMultipleColumns: false))
            {
                return clipboardSnapshot;
            }
        }

        if (IsSnapshotUsable(uiAutomationSnapshot, requireMultipleColumns: false))
        {
            return uiAutomationSnapshot;
        }

        return uiAutomationSnapshot;
    }

    internal static bool IsSnapshotMisaligned(ListViewSnapshot snapshot)
    {
        if (snapshot.Headers.Count == 0 || snapshot.Rows.Count == 0)
        {
            return false;
        }

        var headers = ExternalUtilityColumnNormalizer.NormalizeHeaders(snapshot.Headers);
        foreach (var cells in snapshot.Rows.Take(5))
        {
            var values = ExternalUtilityColumnNormalizer.MapRawRowValues(headers, cells);
            if (ExternalUtilityColumnNormalizer.LooksMisaligned(values))
            {
                return true;
            }
        }

        return false;
    }

    internal static bool IsSnapshotUsableForUiAutomation(ListViewSnapshot snapshot) =>
        IsSnapshotUsable(snapshot, requireMultipleColumns: true);

    internal static bool IsSnapshotUsableForClipboard(ListViewSnapshot snapshot) =>
        IsSnapshotUsable(snapshot, requireMultipleColumns: false);

    private static bool IsSnapshotUsable(ListViewSnapshot snapshot, bool requireMultipleColumns)
    {
        if (snapshot.Rows.Count == 0)
        {
            return false;
        }

        if (!requireMultipleColumns)
        {
            return true;
        }

        var maxCells = snapshot.Rows.Max(row => row.Count);
        return maxCells >= 2 || snapshot.Headers.Count >= 2;
    }

    public static ListViewSnapshot ReadDirect(IntPtr listViewHandle)
    {
        GetWindowRect(listViewHandle, out var rect);
        var rowCount = SendMessage(listViewHandle, LvmGetItemCount, IntPtr.Zero, IntPtr.Zero).ToInt32();
        var headers = ReadHeaders(listViewHandle);
        var columnCount = Math.Max(headers.Count, GuessColumnCount(listViewHandle, rowCount));

        if (headers.Count == 0 && columnCount > 0)
        {
            headers = Enumerable.Range(0, columnCount).Select(i => $"Колонка {i + 1}").ToArray();
        }

        var rows = new List<IReadOnlyList<string>>();
        for (var rowIndex = 0; rowIndex < rowCount; rowIndex++)
        {
            var cells = new List<string>();
            for (var columnIndex = 0; columnIndex < columnCount; columnIndex++)
            {
                cells.Add(ReadSubItemText(listViewHandle, rowIndex, columnIndex));
            }

            while (cells.Count > 0 && string.IsNullOrWhiteSpace(cells[^1]))
            {
                cells.RemoveAt(cells.Count - 1);
            }

            if (cells.Count == 0 || cells.All(string.IsNullOrWhiteSpace))
            {
                continue;
            }

            rows.Add(cells);
        }

        return new ListViewSnapshot(listViewHandle, rect.Top, rect.Left, headers, rows);
    }

    private static int GuessColumnCount(IntPtr listViewHandle, int rowCount)
    {
        if (rowCount == 0)
        {
            return 0;
        }

        var count = 0;
        for (var columnIndex = 0; columnIndex < 32; columnIndex++)
        {
            var text = ReadSubItemText(listViewHandle, 0, columnIndex);
            if (columnIndex > 0 && string.IsNullOrWhiteSpace(text))
            {
                break;
            }

            count++;
        }

        return count;
    }

    private static IReadOnlyList<string> ReadHeaders(IntPtr listViewHandle)
    {
        var headerHandle = SendMessage(listViewHandle, LvmGetHeader, IntPtr.Zero, IntPtr.Zero);
        if (headerHandle == IntPtr.Zero)
        {
            return Array.Empty<string>();
        }

        var count = SendMessage(headerHandle, HdmGetItemCount, IntPtr.Zero, IntPtr.Zero).ToInt32();
        var headers = new List<string>();
        for (var index = 0; index < count; index++)
        {
            headers.Add(ReadHeaderText(headerHandle, index));
        }

        return headers;
    }

    private static string ReadHeaderText(IntPtr headerHandle, int index)
    {
        var buffer = Marshal.AllocHGlobal(512 * 2);
        try
        {
            var item = new Hditem
            {
                Mask = HdiText,
                PszText = buffer,
                CchTextMax = 512
            };

            var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<Hditem>());
            try
            {
                Marshal.StructureToPtr(item, pointer, false);
                if (SendMessage(headerHandle, HdmGetItemW, new IntPtr(index), pointer) == IntPtr.Zero)
                {
                    return "";
                }

                item = Marshal.PtrToStructure<Hditem>(pointer)!;
                return Marshal.PtrToStringUni(item.PszText)?.Trim() ?? "";
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string ReadSubItemText(IntPtr listViewHandle, int rowIndex, int columnIndex)
    {
        var buffer = Marshal.AllocHGlobal(4096 * 2);
        try
        {
            var item = new Lvitem
            {
                Mask = LvifText,
                ItemIndex = rowIndex,
                SubItemIndex = columnIndex,
                PszText = buffer,
                TextMax = 4096
            };

            var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<Lvitem>());
            try
            {
                Marshal.StructureToPtr(item, pointer, false);
                SendMessage(listViewHandle, LvmGetItemTextW, IntPtr.Zero, pointer);
                item = Marshal.PtrToStructure<Lvitem>(pointer)!;
                return TextSanitizer.NormalizeDisplay(Marshal.PtrToStringUni(item.PszText) ?? "", 500);
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Lvitem
    {
        public int Mask;
        public int ItemIndex;
        public int SubItemIndex;
        public int State;
        public int StateMask;
        public IntPtr PszText;
        public int TextMax;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Hditem
    {
        public int Mask;
        public int Cxy;
        public IntPtr PszText;
        public IntPtr Hbm;
        public int CchTextMax;
        public int Fmt;
        public IntPtr LParam;
        public int IImage;
        public int IOrder;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hWnd, out Rect lpRect);
}

internal static class Win32ControlEnumerator
{
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    public static IReadOnlyList<IntPtr> FindListViews(IntPtr rootWindow)
    {
        var handles = new List<IntPtr>();
        CollectListViews(rootWindow, handles);
        return handles.Distinct().ToArray();
    }

    private static void CollectListViews(IntPtr parent, List<IntPtr> handles)
    {
        EnumChildWindows(parent, (hWnd, _) =>
        {
            if (GetClassName(hWnd).Equals("SysListView32", StringComparison.OrdinalIgnoreCase))
            {
                handles.Add(hWnd);
            }

            CollectListViews(hWnd, handles);
            return true;
        }, IntPtr.Zero);
    }

    private static string GetClassName(IntPtr hWnd)
    {
        var builder = new StringBuilder(256);
        GetClassName(hWnd, builder, builder.Capacity);
        return builder.ToString();
    }

    [DllImport("user32.dll")]
    private static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
}
