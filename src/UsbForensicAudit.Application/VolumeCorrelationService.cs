using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public static class VolumeCorrelationService
{
    private static readonly Regex VolumeSerialRegex = new(
        @"(?:VolumeSerial(?:Number)?|VSN)\s*[=:]\s*(?<value>[0-9A-F]{4,16}(?:-[0-9A-F]{4,16})?)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex DriveRegex = new(
        @"(?<![A-Z0-9])(?<drive>[A-Z]:)(?:\\|$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static void Process(AuditResult result)
    {
        var mappings = result.Devices
            .Where(x => x.DeviceType.Equals("VolumeMapping", StringComparison.OrdinalIgnoreCase))
            .SelectMany(x => x.Volumes)
            .ToList();

        MergeRegistryAliases(mappings);
        AttachMappingsToDevices(result.Devices, mappings);
        CorrelatePartitionEvents(result, mappings);
        CorrelateArtifactVolumeSerials(result);
    }

    private static void CorrelatePartitionEvents(AuditResult result, IReadOnlyList<VolumeIdentity> mappings)
    {
        foreach (var evidence in result.Evidence.Where(x =>
                     x.EventId == "1006"
                     && (x.Provider.Contains("Partition", StringComparison.OrdinalIgnoreCase)
                         || x.Source.Contains("Partition", StringComparison.OrdinalIgnoreCase))))
        {
            var candidates = mappings.Where(mapping =>
                    ContainsIdentifier(evidence.RawText, mapping.VolumeGuid)
                    || ContainsIdentifier(evidence.RawText, mapping.DiskId)
                    || ContainsIdentifier(evidence.RawText, mapping.DiskSignature))
                .ToArray();
            if (candidates.Length == 0)
            {
                continue;
            }

            var device = result.Devices.Where(IsPhysicalDevice)
                .FirstOrDefault(x => EvidenceIdentifiesDevice(evidence, x));
            if (device is null)
            {
                continue;
            }

            var serialMatch = VolumeSerialRegex.Match(evidence.RawText);
            foreach (var mapping in candidates)
            {
                var linked = CloneWithProvenance(mapping, $"Partition/Diagnostic Event 1006 record {evidence.RecordId}");
                if (serialMatch.Success)
                {
                    linked.VolumeSerialNumber = NormalizeSerial(serialMatch.Groups["value"].Value);
                }
                AddVolume(device, linked);
            }
            PopulateDeviceHints(device);
        }
    }

    private static void MergeRegistryAliases(List<VolumeIdentity> mappings)
    {
        foreach (var group in mappings.Where(x => Fingerprint(x).Length > 0)
                     .GroupBy(Fingerprint, StringComparer.OrdinalIgnoreCase))
        {
            var drive = group.Select(x => x.DriveLetter).FirstOrDefault(x => x.Length > 0) ?? "";
            var volumeGuid = group.Select(x => x.VolumeGuid).FirstOrDefault(x => x.Length > 0) ?? "";
            foreach (var mapping in group)
            {
                if (mapping.DriveLetter.Length == 0)
                {
                    mapping.DriveLetter = drive;
                }
                if (mapping.VolumeGuid.Length == 0)
                {
                    mapping.VolumeGuid = volumeGuid;
                }
                mapping.Provenance.Add($"MountedDevices alias fingerprint {group.Key}");
            }
        }
    }

    private static void AttachMappingsToDevices(IList<UsbDeviceRecord> devices, IReadOnlyList<VolumeIdentity> mappings)
    {
        foreach (var device in devices.Where(IsPhysicalDevice))
        {
            foreach (var mapping in mappings)
            {
                var reason = StrongDeviceReason(device, mapping);
                if (reason.Length == 0 && mapping.DriveLetter.Length > 0
                    && device.Volumes.Any(x =>
                        x.Source.Contains("WMI", StringComparison.OrdinalIgnoreCase)
                        && x.DriveLetter.Equals(mapping.DriveLetter, StringComparison.OrdinalIgnoreCase)))
                {
                    reason = $"Live WMI disk association confirms {mapping.DriveLetter}";
                }

                if (reason.Length == 0)
                {
                    continue;
                }

                AddVolume(device, CloneWithProvenance(mapping, reason));
            }
            PopulateDeviceHints(device);
        }
    }

    private static void CorrelateArtifactVolumeSerials(AuditResult result)
    {
        var additions = new List<EvidenceRecord>();
        foreach (var artifact in result.Evidence.Where(IsUserVolumeArtifact).ToArray())
        {
            var serialMatch = VolumeSerialRegex.Match($"{artifact.DeviceHint}\n{artifact.RawText}");
            if (!serialMatch.Success)
            {
                continue; // A drive letter alone is never sufficient.
            }

            var serial = NormalizeSerial(serialMatch.Groups["value"].Value);
            var drive = DriveRegex.Match($"{artifact.DeviceHint}\n{artifact.RawText}").Groups["drive"].Value.ToUpperInvariant();
            foreach (var device in result.Devices.Where(IsPhysicalDevice))
            {
                var matchedVolumes = device.Volumes
                    .Where(x => NormalizeSerial(x.VolumeSerialNumber).Equals(serial, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                if (matchedVolumes.Length == 0)
                {
                    continue;
                }

                var confidence = drive.Length > 0 && matchedVolumes.Any(x => x.DriveLetter.Equals(drive, StringComparison.OrdinalIgnoreCase))
                    ? "High"
                    : "Medium";
                foreach (var volume in matchedVolumes)
                {
                    volume.Provenance.Add($"{artifact.Source}: exact VSN {serial}; drive={drive}; confidence={confidence}");
                }

                additions.Add(new EvidenceRecord
                {
                    TimestampUtc = artifact.TimestampUtc,
                    Source = "Volume Correlation",
                    Provider = artifact.Source,
                    EventId = confidence,
                    DeviceHint = device.CanonicalDeviceId,
                    EvidenceCategory = "Volume/device correlation",
                    EvidenceStrength = "Corroborating",
                    Confidence = confidence,
                    UserExplanation = "Связь основана на точном серийном номере тома; одна буква диска не использовалась как доказательство.",
                    Summary = $"{artifact.Source} -> {device.DisplayName}: exact VolumeSerialNumber={serial}, confidence={confidence}",
                    Provenance =
                        $"Derived from {artifact.Provenance}; exact VSN={serial}; canonical={device.CanonicalDeviceId}",
                    CanEstablishConnectionDate = false,
                    RawText = $"Artifact={artifact.SourceRecord}\nVSN={serial}\nDrive={drive}\nCanonicalDevice={device.CanonicalDeviceId}"
                });
            }
        }
        result.Evidence.AddRange(additions);
    }

    private static string StrongDeviceReason(UsbDeviceRecord device, VolumeIdentity mapping)
    {
        if (mapping.DevicePath.Length == 0)
        {
            return "";
        }

        var path = mapping.DevicePath.Replace('#', '\\');
        var instance = device.DeviceInstanceId.Replace('#', '\\');
        if (instance.Length >= 8 && path.Contains(instance, StringComparison.OrdinalIgnoreCase))
        {
            return "MountedDevices path contains exact PnP instance ID";
        }

        if (DeviceIdentityGraph.IsHardwareSerial(device.Serial)
            && PathContainsToken(path, DeviceIdentityGraph.NormalizeSerial(device.Serial)))
        {
            return $"MountedDevices path contains exact hardware serial {DeviceIdentityGraph.NormalizeSerial(device.Serial)}";
        }

        return "";
    }

    private static bool PathContainsToken(string path, string token)
    {
        var tokens = path.Split(['\\', '#', '&', '{', '}', '_'], StringSplitOptions.RemoveEmptyEntries);
        return tokens.Any(x => x.Equals(token, StringComparison.OrdinalIgnoreCase))
               || path.Contains($@"\{token}\", StringComparison.OrdinalIgnoreCase);
    }

    private static bool EvidenceIdentifiesDevice(EvidenceRecord evidence, UsbDeviceRecord device)
    {
        var text = $"{evidence.DeviceHint}\n{evidence.RawText}".Replace('#', '\\');
        if (device.DeviceInstanceId.Length >= 8
            && text.Contains(device.DeviceInstanceId.Replace('#', '\\'), StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return DeviceIdentityGraph.IsHardwareSerial(device.Serial)
               && PathContainsToken(text, DeviceIdentityGraph.NormalizeSerial(device.Serial));
    }

    private static bool ContainsIdentifier(string text, string identifier) =>
        identifier.Length >= 8
        && text.Replace("-", "", StringComparison.Ordinal)
            .Contains(identifier.Replace("-", "", StringComparison.Ordinal), StringComparison.OrdinalIgnoreCase);

    private static void AddVolume(UsbDeviceRecord device, VolumeIdentity volume)
    {
        var existing = device.Volumes.FirstOrDefault(x =>
            (x.MappingName.Length > 0 && x.MappingName.Equals(volume.MappingName, StringComparison.OrdinalIgnoreCase))
            || (Fingerprint(x).Length > 0 && Fingerprint(x).Equals(Fingerprint(volume), StringComparison.OrdinalIgnoreCase)));
        if (existing is null)
        {
            device.Volumes.Add(volume);
            return;
        }

        existing.DriveLetter = First(existing.DriveLetter, volume.DriveLetter);
        existing.VolumeGuid = First(existing.VolumeGuid, volume.VolumeGuid);
        existing.VolumeSerialNumber = First(existing.VolumeSerialNumber, volume.VolumeSerialNumber);
        existing.Provenance = existing.Provenance.Concat(volume.Provenance).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static VolumeIdentity CloneWithProvenance(VolumeIdentity source, string reason) => new()
    {
        MappingName = source.MappingName,
        VolumeGuid = source.VolumeGuid,
        VolumeSerialNumber = source.VolumeSerialNumber,
        DiskSignature = source.DiskSignature,
        DiskId = source.DiskId,
        PartitionOffset = source.PartitionOffset,
        DriveLetter = source.DriveLetter,
        DevicePath = source.DevicePath,
        Source = source.Source,
        Confidence = "High",
        Provenance = source.Provenance.Concat([reason]).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
    };

    private static void PopulateDeviceHints(UsbDeviceRecord device)
    {
        device.DriveLetters = string.Join(", ", device.Volumes.Select(x => x.DriveLetter)
            .Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase));
        device.VolumeHints = string.Join("; ", device.Volumes.SelectMany(x => new[]
        {
            x.VolumeGuid.Length > 0 ? $"VolumeGuid={x.VolumeGuid}" : "",
            x.VolumeSerialNumber.Length > 0 ? $"VSN={x.VolumeSerialNumber}" : "",
            x.DiskSignature.Length > 0 ? $"DiskSignature={x.DiskSignature}" : "",
            x.DiskId.Length > 0 ? $"DiskId={x.DiskId}" : ""
        }).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase));
    }

    private static string Fingerprint(VolumeIdentity volume)
    {
        if (volume.DevicePath.Length > 0)
        {
            return $"PATH:{volume.DevicePath.ToUpperInvariant()}";
        }
        if (volume.DiskId.Length > 0)
        {
            return $"GPT:{volume.DiskId}";
        }
        if (volume.DiskSignature.Length > 0 && volume.PartitionOffset.HasValue)
        {
            return $"MBR:{volume.DiskSignature}:{volume.PartitionOffset}";
        }
        return "";
    }

    private static bool IsPhysicalDevice(UsbDeviceRecord device) =>
        !device.DeviceType.Equals("VolumeMapping", StringComparison.OrdinalIgnoreCase)
        && !device.VisualCategory.Equals("SupportArtifact", StringComparison.OrdinalIgnoreCase)
        && !device.VisualCategory.Equals("UsbFlagsTrace", StringComparison.OrdinalIgnoreCase);

    private static bool IsUserVolumeArtifact(EvidenceRecord evidence) =>
        evidence.Source.Contains("LNK", StringComparison.OrdinalIgnoreCase)
        || evidence.Source.Contains("JumpList", StringComparison.OrdinalIgnoreCase)
        || evidence.Source.Contains("Partition", StringComparison.OrdinalIgnoreCase);

    private static string NormalizeSerial(string value) =>
        value.Replace("-", "", StringComparison.Ordinal).Trim().ToUpperInvariant();

    private static string First(string first, string second) => first.Length > 0 ? first : second;
}
