using System.Windows;
using System.Windows.Controls;

namespace UsbForensicAudit;

/// <summary>
/// Заметки эксперта во вкладке «Следы очистки»: выделил находку — увидел её
/// заметку, отредактировал — сохранил. Заметка хранится в audit.sqlite по
/// стабильному ключу находки (ExpertNotes.KeyOf), поэтому после повторного
/// сканирования возвращается к тем же следам и попадает в отчёты.
/// </summary>
public partial class MainWindow
{
    private void FindingsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var finding = FindingsGrid.SelectedItem as CleanupFinding;
        ExpertNoteTextBox.Text = finding?.ExpertNote ?? "";
        ExpertNoteStatusText.Text = finding is null
            ? "Выделите находку в таблице, чтобы добавить заметку."
            : "";
    }

    private void SaveExpertNoteButton_Click(object sender, RoutedEventArgs e)
    {
        if (FindingsGrid.SelectedItem is not CleanupFinding finding)
        {
            ExpertNoteStatusText.Text = "Сначала выделите находку в таблице.";
            return;
        }

        try
        {
            var note = ExpertNoteTextBox.Text.Trim();
            finding.ExpertNote = note;
            _vm.Storage.SaveExpertNote(ExpertNotes.KeyOf(finding), note);
            FindingsGrid.Items.Refresh();
            ExpertNoteStatusText.Text = note.Length == 0
                ? "Заметка удалена."
                : "Заметка сохранена — она попадёт в отчёты и вернётся при следующем сканировании.";
        }
        catch (Exception exception)
        {
            AppLog.Error(exception, "Expert note save failed");
            MessageBox.Show(this, exception.Message, "Не удалось сохранить заметку", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>Возвращает сохранённые заметки на находки свежего результата.</summary>
    private void ApplyExpertNotes(AuditResult result)
    {
        try
        {
            ExpertNotes.Apply(result.CleanupFindings, _vm.Storage.LoadExpertNotes());
        }
        catch (Exception exception)
        {
            // Недоступность заметок не должна мешать показу результата сканирования.
            AppLog.Error(exception, "Expert notes load failed");
        }
    }
}
