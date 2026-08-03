using System.Windows.Controls;

namespace UsbForensicAudit;

public static class DataGridAutoSize
{
    /// <summary>
    /// Свыше этого числа строк авто-подгонка по содержимому не выполняется:
    /// SizeToCells измеряет каждую видимую ячейку в UI-потоке и на тысячах
    /// строк даёт секундные замирания. Такие таблицы остаются с ширинами
    /// колонок из XAML.
    /// </summary>
    private const int MaxRowsForAutoSize = 400;

    public static void FitColumns(DataGrid grid)
    {
        if (grid.Columns.Count == 0)
        {
            return;
        }

        if (grid.Items.Count > MaxRowsForAutoSize)
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
