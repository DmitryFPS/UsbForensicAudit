using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Windows;

namespace UsbForensicAudit;

/// <summary>
/// Показывает всю историю одной сетевой связи: когда соединялись, сколько
/// держалось соединение, какие папки и адреса открывали, что скачивали. У каждой
/// строки видно, откуда она взята и что означает её время, — иначе список нечем
/// проверить.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "WPF-окно")]
public partial class NetworkConnectionDetailsWindow : Window
{
    private readonly NetworkConnectionRecord _connection;

    public NetworkConnectionDetailsWindow(NetworkConnectionRecord connection)
    {
        InitializeComponent();
        _connection = connection;
        DarkWindowChrome.Apply(this);

        TitleText.Text = $"{connection.KindText}: {connection.TargetText}";
        SummaryText.Text = connection.DetailsText;
        FactsText.Text = NetworkConnectionFacts.Describe(connection);

        VisitsGrid.ItemsSource = connection.Visits;
        SessionsGrid.ItemsSource = connection.Sessions;

        if (connection.Visits.Count == 0 && connection.Sessions.Count == 0)
        {
            WarningText.Text = "У этой связи нет ни сеансов, ни обращений: известен только сам факт "
                               + "связи. Так бывает, когда журнал вытеснен по размеру или выключен, а в "
                               + "реестре осталась одна запись о сети.";
            WarningText.Visibility = Visibility.Visible;
        }
    }

    private void CopyButton_Click(object sender, RoutedEventArgs e)
    {
        var text = new StringBuilder();
        text.AppendLine(NetworkConnectionFacts.Describe(_connection));
        text.AppendLine();

        text.AppendLine("Куда ходили:");
        foreach (var visit in _connection.Visits)
        {
            text.AppendLine($"{visit.WhenText}\t{visit.KindText}\t{visit.TargetText}\t{visit.TitleText}"
                            + $"\t{visit.UserText}\t{visit.CountText}\t{visit.SourceText}\t{visit.Provenance}");
        }

        text.AppendLine();
        text.AppendLine("Сеансы связи:");
        foreach (var session in _connection.Sessions)
        {
            text.AppendLine($"{session.StartedText}\t{session.EndedText}\t{session.DurationText}"
                            + $"\t{session.OutcomeText}\t{session.ReasonText}\t{session.SourceText}"
                            + $"\t{session.Provenance}");
        }

        try
        {
            Clipboard.SetText(text.ToString());
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, $"Не удалось скопировать в буфер: {exception.Message}",
                "История сетевой связи", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
