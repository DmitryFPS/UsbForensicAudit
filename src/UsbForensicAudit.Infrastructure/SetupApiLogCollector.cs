using System.IO;

namespace UsbForensicAudit;

public sealed class SetupApiLogCollector : IEvidenceCollector
{
    public string ProgressMessage => "Парсинг setupapi.dev.log...";

    public bool ShouldRun => true;

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings)
    {
        var evidence = new List<EvidenceRecord>();
        var infDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "inf");
        string[] paths;

        try
        {
            paths = Directory.Exists(infDirectory)
                ? Directory.EnumerateFiles(infDirectory, "setupapi.dev*.log*", SearchOption.TopDirectoryOnly)
                    .OrderByDescending(path => Path.GetFileName(path).Equals("setupapi.dev.log", StringComparison.OrdinalIgnoreCase))
                    .ThenByDescending(File.GetLastWriteTimeUtc)
                    .ToArray()
                : [];
        }
        catch (Exception ex)
        {
            warnings.Add($"Не удалось перечислить журналы SetupAPI в {infDirectory}: {ex.Message}");
            return evidence;
        }

        if (paths.Length == 0)
        {
            warnings.Add($"setupapi.dev.log и архивы не найдены: {infDirectory}");
            return evidence;
        }

        var deduplicationKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths)
        {
            try
            {
                using var reader = File.OpenText(path);
                var sourceName = Path.GetFileName(path);
                foreach (var record in SetupApiLogParser.Parse(reader, sourceName, path))
                {
                    var key = string.Join(
                        "\u001f",
                        record.Source,
                        record.Summary,
                        record.DeviceHint,
                        record.TimestampUtc.ToString("O"));
                    if (deduplicationKeys.Add(key))
                    {
                        evidence.Add(record);
                    }
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Ошибка чтения {path}: {ex.Message}");
            }
        }

        return evidence;
    }
}
