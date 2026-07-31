using System.IO;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class LiveNetworkProbe
{
    [Fact]
    public void Dump()
    {
        var warnings = new List<string>();
        var sets = new[]
        {
            new NetworkProfileCollector().Collect(warnings),
            new NetworkEventLogCollector().Collect(warnings),
            new NetworkShareArtifactCollector().Collect(warnings),
            new BluetoothArtifactCollector().Collect(warnings),
            new BrowserHistoryCollector().Collect(warnings)
        };

        var merged = NetworkConnectionMerger.Merge(sets.SelectMany(x => x.Connections).ToList());

        var lines = new List<string> { NetworkConnectionSummary.Create(merged).Describe(), "" };
        foreach (var item in merged)
        {
            lines.Add($"[{item.KindText}] {item.TargetText}");
            lines.Add($"    первое: {item.FirstSeenText}  ({item.FirstSeenProvenance})");
            lines.Add($"    последнее: {item.LastSeenText}");
            lines.Add($"    защита: {item.SecurityText}");
            lines.Add($"    подключение: {item.AdapterText}");
            lines.Add($"    адреса: {item.LocalAddressesText}");
            lines.Add($"    активность: {item.ActivityText}");
            lines.Add($"    пояснение: {item.DetailsText}");
            lines.Add($"    источники: {item.SourcesText}");
            foreach (var session in item.Sessions.Take(12))
            {
                lines.Add($"      сеанс: {session.StartedText} -> {session.EndedText} "
                          + $"[{session.DurationText}] {session.OutcomeText} | {session.ReasonText}");
            }

            if (item.Sessions.Count > 12)
            {
                lines.Add($"      ... всего сеансов: {item.Sessions.Count}");
            }

            foreach (var visit in item.Visits)
            {
                lines.Add($"      -> {visit.KindText}: {visit.TargetText} [{visit.WhenText}] "
                          + $"{visit.MentionCountText}; {visit.SourceText}; {visit.TitleText}");
            }

            lines.Add("");
        }

        lines.Add("=== записи доказательств");
        foreach (var record in sets.SelectMany(x => x.Evidence))
        {
            lines.Add($"  {record.Source} | {record.EvidenceCategory} | {record.Summary}");
        }

        lines.Add("=== предупреждения");
        lines.AddRange(warnings.Select(x => "  " + x));

        File.WriteAllLines(Path.Combine(Path.GetTempPath(), "netlive.txt"), lines);
    }
}
