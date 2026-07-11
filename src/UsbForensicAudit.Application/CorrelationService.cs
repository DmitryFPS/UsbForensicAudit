namespace UsbForensicAudit;

public sealed class CorrelationService
{
    public IReadOnlyList<EvidenceRecord> BuildDeviceCorrelations(AuditResult result)
    {
        var records = new List<EvidenceRecord>();
        var searchableEvidence = result.Evidence
            .Where(x => !x.Source.Equals("Correlation", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        foreach (var device in result.Devices.Where(IsRealDevice).Take(400))
        {
            var tokens = DeviceEvidenceTokens.Build(device).ToArray();
            if (tokens.Length == 0)
            {
                continue;
            }

            var matches = searchableEvidence
                .Select(e => new { Evidence = e, Hits = tokens.Count(t => DeviceEvidenceTokens.Contains(e, t)) })
                .Where(x => x.Hits > 0)
                .OrderByDescending(x => x.Hits)
                .ThenByDescending(x => x.Evidence.TimestampUtc)
                .Take(30)
                .ToArray();

            if (matches.Length == 0)
            {
                continue;
            }

            var sources = matches.Select(x => x.Evidence.Source).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToArray();
            var firstSeen = matches.Min(x => x.Evidence.TimestampUtc);
            var lastSeen = matches.Max(x => x.Evidence.TimestampUtc);
            var confidence = GetConfidence(tokens.Length, matches.Length, sources.Length);

            records.Add(new EvidenceRecord
            {
                TimestampUtc = lastSeen,
                Source = "Correlation",
                EventId = confidence,
                EvidenceCategory = "Correlation",
                EvidenceStrength = "Corroborating",
                Confidence = confidence,
                DeviceHint = device.DeviceInstanceId,
                Summary = $"{device.DisplayName}: {matches.Length} related evidence records across {sources.Length} sources; first={firstSeen:u}; last={lastSeen:u}",
                Provenance =
                    $"Derived correlation; canonical={device.CanonicalDeviceId}; sources={string.Join(", ", sources)}; tokens={string.Join(", ", tokens)}",
                CanEstablishConnectionDate = false,
                RawText = string.Join(Environment.NewLine, new[]
                {
                    $"Device={device.DisplayName}",
                    $"InstanceId={device.DeviceInstanceId}",
                    $"VID/PID={device.Vid}/{device.Pid}",
                    $"Serial={device.Serial}",
                    $"ContainerId={device.ContainerId}",
                    $"Confidence={confidence}",
                    $"Sources={string.Join(", ", sources)}",
                    $"Tokens={string.Join(", ", tokens)}",
                    "TopMatches:"
                }.Concat(matches.Take(12).Select(x => $"- [{x.Evidence.Source}] {x.Evidence.TimestampUtc:u} {x.Evidence.Summary}")))
            });
        }

        return records;
    }

    private static bool IsRealDevice(UsbDeviceRecord device)
    {
        return !device.Source.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase)
               && !string.IsNullOrWhiteSpace(device.DeviceInstanceId)
               && !device.DeviceType.Equals("VolumeMapping", StringComparison.OrdinalIgnoreCase)
               && (string.IsNullOrWhiteSpace(device.CanonicalDeviceId) || device.IsCanonicalPrimary);
    }

    private static string GetConfidence(int tokenCount, int matchCount, int sourceCount)
    {
        if (sourceCount >= 4 && matchCount >= 8 && tokenCount >= 3)
        {
            return "High";
        }

        if (sourceCount >= 2 && matchCount >= 3)
        {
            return "Medium";
        }

        return "Low";
    }
}
