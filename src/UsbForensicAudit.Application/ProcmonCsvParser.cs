using System.Globalization;
using System.IO;
using System.Text;

namespace UsbForensicAudit;

public sealed class ProcmonRegistryEvent
{
    public required DateTimeOffset Timestamp { get; init; }
    public required string ProcessName { get; init; }
    public required int ProcessId { get; init; }
    public required string Operation { get; init; }
    public required string Path { get; init; }
    public required string Result { get; init; }
    public string Detail { get; init; } = "";
}

public static class ProcmonCsvParser
{
    public static IReadOnlyList<ProcmonRegistryEvent> ParseFile(string csvPath)
    {
        if (!File.Exists(csvPath))
        {
            return [];
        }

        var lines = File.ReadAllLines(csvPath, Encoding.UTF8);
        if (lines.Length <= 1)
        {
            return [];
        }

        var headers = ParseCsvLine(lines[0]);
        var events = new List<ProcmonRegistryEvent>();
        for (var index = 1; index < lines.Length; index++)
        {
            if (string.IsNullOrWhiteSpace(lines[index]))
            {
                continue;
            }

            var fields = ParseCsvLine(lines[index]);
            if (fields.Count == 0)
            {
                continue;
            }

            var mapped = MapRow(headers, fields);
            if (mapped is null)
            {
                continue;
            }

            events.Add(mapped);
        }

        return events;
    }

    public static IReadOnlyList<ExternalUtilitySourceHit> ToSourceHits(
        IReadOnlyList<ProcmonRegistryEvent> events,
        ExternalUtilityRow row,
        ExternalUtilityIdentifierInfo identifier,
        string utilityProcessName,
        int maxHits = 8)
    {
        var needles = ProcmonNeedleMatcher.BuildNeedles(row, identifier);
        var isOtherTraces = row.IsOtherTracesSection;
        var utilityBaseName = Path.GetFileNameWithoutExtension(utilityProcessName);
        if (string.IsNullOrWhiteSpace(utilityBaseName))
        {
            utilityBaseName = utilityProcessName;
        }

        var ranked = events
            .Where(e => IsRegistryOperation(e.Operation))
            .Where(e =>
            {
                var eventBaseName = Path.GetFileNameWithoutExtension(e.ProcessName);
                return e.ProcessName.Equals(utilityProcessName, StringComparison.OrdinalIgnoreCase)
                       || e.ProcessName.Equals(utilityBaseName, StringComparison.OrdinalIgnoreCase)
                       || eventBaseName.Equals(utilityBaseName, StringComparison.OrdinalIgnoreCase);
            })
            .Select(e =>
            {
                var classification = ProcmonRegistryPathClassifier.Classify(e.Path);
                var needleMatch = ProcmonNeedleMatcher.MatchesPathOrDetail(e.Path, e.Detail, needles);
                var score = classification.Rank + (needleMatch ? 200 : 0);
                if (e.Result.Contains("SUCCESS", StringComparison.OrdinalIgnoreCase))
                {
                    score += 5;
                }

                return (Event: e, Classification: classification, NeedleMatch: needleMatch, Score: score);
            })
            .Where(x => x.NeedleMatch
                        || needles.Count == 0
                        || (isOtherTraces && x.Classification.IsIndirectSource))
            .OrderByDescending(x => x.Score)
            .ThenByDescending(x => x.Event.Timestamp)
            .ToArray();

        if (ranked.Length == 0)
        {
            ranked = events
                .Where(e => IsRegistryOperation(e.Operation))
                .Where(e =>
                {
                    var eventBaseName = Path.GetFileNameWithoutExtension(e.ProcessName);
                    return e.ProcessName.Equals(utilityProcessName, StringComparison.OrdinalIgnoreCase)
                           || e.ProcessName.Equals(utilityBaseName, StringComparison.OrdinalIgnoreCase)
                           || eventBaseName.Equals(utilityBaseName, StringComparison.OrdinalIgnoreCase);
                })
                .OrderByDescending(e => e.Timestamp)
                .Take(maxHits)
                .Select(e => (Event: e, Classification: ProcmonRegistryPathClassifier.Classify(e.Path), NeedleMatch: false, Score: 0))
                .ToArray();
        }

        var hits = new List<ExternalUtilitySourceHit>();
        foreach (var item in ranked
                     .GroupBy(x => x.Event.Path, StringComparer.OrdinalIgnoreCase)
                     .Select(g => g.OrderByDescending(x => x.Score).First())
                     .OrderByDescending(x => x.Score)
                     .Take(maxHits))
        {
            hits.Add(new ExternalUtilitySourceHit
            {
                Title = $"Procmon: {item.Classification.Title}",
                RegistryPath = item.Event.Path,
                Found = true,
                ResultText = BuildResultText(item.Event, item.Classification, item.NeedleMatch),
                LikelyUsbDetectorSource = item.Classification.IsDirectSource || item.Classification.IsIndirectSource,
                IsProcmonEvidence = true,
                Operation = item.Event.Operation,
                ObservedAtUtc = item.Event.Timestamp,
                EvidenceRank = item.Score
            });
        }

        return hits;
    }

    private static string BuildResultText(
        ProcmonRegistryEvent registryEvent,
        ProcmonRegistryPathClassifier.Classification classification,
        bool needleMatch)
    {
        var matchNote = needleMatch ? "совпадение с VID/PID строки" : "чтение реестра процессом утилиты";
        var kind = classification.IsDirectSource
            ? "прямой ключ реестра USB"
            : classification.IsIndirectSource
                ? "косвенный ключ Windows"
                : "запись реестра";

        return $"{registryEvent.Operation} → {kind}; {matchNote}; Result={registryEvent.Result}";
    }

    private static bool IsRegistryOperation(string operation) =>
        operation.StartsWith("Reg", StringComparison.OrdinalIgnoreCase);

    private static ProcmonRegistryEvent? MapRow(IReadOnlyList<string> headers, IReadOnlyList<string> fields)
    {
        string Get(params string[] names)
        {
            foreach (var name in names)
            {
                var index = IndexOfHeader(headers, name);
                if (index >= 0 && index < fields.Count)
                {
                    return fields[index].Trim();
                }
            }

            return "";
        }

        var operation = Get("Operation");
        var path = Get("Path");
        if (string.IsNullOrWhiteSpace(operation) || string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        if (!IsRegistryOperation(operation))
        {
            return null;
        }

        var timeText = Get("Time of Day", "Time");
        var timestamp = ParseProcmonTime(timeText);
        var pidText = Get("PID");
        _ = int.TryParse(pidText, out var pid);

        return new ProcmonRegistryEvent
        {
            Timestamp = timestamp,
            ProcessName = Get("Process Name"),
            ProcessId = pid,
            Operation = operation,
            Path = path,
            Result = Get("Result"),
            Detail = Get("Detail")
        };
    }

    private static int IndexOfHeader(IReadOnlyList<string> headers, string name)
    {
        for (var index = 0; index < headers.Count; index++)
        {
            if (headers[index].Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return index;
            }
        }

        return -1;
    }

    private static DateTimeOffset ParseProcmonTime(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return DateTimeOffset.Now;
        }

        var formats = new[]
        {
            "HH:mm:ss.fffffff",
            "HH:mm:ss.ffffff",
            "HH:mm:ss.fff",
            "HH:mm:ss"
        };

        if (DateTime.TryParseExact(text.Trim(), formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var todayTime))
        {
            var today = DateTime.Today;
            return new DateTimeOffset(today.Year, today.Month, today.Day, todayTime.Hour, todayTime.Minute, todayTime.Second, todayTime.Millisecond, TimeSpan.Zero);
        }

        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsed)
            ? parsed
            : DateTimeOffset.Now;
    }

    private static List<string> ParseCsvLine(string line)
    {
        var result = new List<string>();
        var builder = new StringBuilder();
        var inQuotes = false;

        for (var index = 0; index < line.Length; index++)
        {
            var ch = line[index];
            if (ch == '"')
            {
                if (inQuotes && index + 1 < line.Length && line[index + 1] == '"')
                {
                    builder.Append('"');
                    index++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }

                continue;
            }

            if (ch == ',' && !inQuotes)
            {
                result.Add(builder.ToString());
                builder.Clear();
                continue;
            }

            builder.Append(ch);
        }

        result.Add(builder.ToString());
        return result;
    }
}
