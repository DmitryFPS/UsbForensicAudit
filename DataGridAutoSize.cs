using System.Windows.Controls;

namespace UsbForensicAudit;

public static class DataGridAutoSize
{
    public static void FitColumns(DataGrid grid)
    {
        if (grid.Columns.Count == 0)
        {
            return;
        }

        grid.UpdateLayout();
        grid.Dispatcher.BeginInvoke(() =>
        {
            foreach (var column in grid.Columns)
            {
                column.MinWidth = 60;
                column.Width = new DataGridLength(1, DataGridLengthUnitType.SizeToCells);
            }

            grid.UpdateLayout();
        }, System.Windows.Threading.DispatcherPriority.Loaded);
    }
}
