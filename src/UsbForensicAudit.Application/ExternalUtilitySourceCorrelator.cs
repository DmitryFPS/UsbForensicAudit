using System.Text;

namespace UsbForensicAudit;

public static class ExternalUtilitySourceCorrelator
{
    public static IReadOnlyList<ExternalUtilitySourceHit> Correlate(
        ExternalUtilityIdentifierInfo identifier,
        AuditResult? audit,
        IExternalUtilityRegistryTracer? registryTracer = null)
    {
        var hits = new List<ExternalUtilitySourceHit>();

        if (audit is not null && identifier.HasVid)
        {
            AppendAuditDeviceHits(identifier, audit, hits);
            AppendAuditEvidenceHits(identifier, audit, hits);
        }

        if (identifier.HasVid && registryTracer is not null)
        {
            foreach (var liveHit in registryTracer.Trace(identifier.Vid, identifier.Pid))
            {
                if (hits.Any(x => x.Title.StartsWith(liveHit.Title, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                hits.Add(liveHit);
            }
        }

        if (hits.Count == 0)
        {
            hits.Add(new ExternalUtilitySourceHit
            {
                Title = "Идентификатор",
                RegistryPath = "—",
                Found = false,
                ResultText = identifier.HasVid
                    ? "не удалось сопоставить VID/PID с известными ветками"
                    : "VID/PID не распознан в строке утилиты",
                LikelyUsbDetectorSource = false
            });
        }

        return hits;
    }

    public static IReadOnlyList<ExternalUtilitySourceHit> MergeProcmonHits(
        IReadOnlyList<ExternalUtilitySourceHit> baseHits,
        IReadOnlyList<ExternalUtilitySourceHit> procmonHits)
    {
        if (procmonHits.Count == 0)
        {
            return baseHits;
        }

        var merged = new List<ExternalUtilitySourceHit>();
        merged.AddRange(procmonHits.OrderByDescending(x => x.EvidenceRank));

        foreach (var hit in baseHits)
        {
            if (hit.IsProcmonEvidence)
            {
                continue;
            }

            if (procmonHits.Any(x => x.Found
                                     && PathsEquivalent(x.RegistryPath, hit.RegistryPath)))
            {
                continue;
            }

            merged.Add(hit);
        }

        return merged;
    }

    public static string FormatSourceChecks(
        IReadOnlyList<ExternalUtilitySourceHit> hits,
        bool isUsbDetector,
        bool isOtherTraces)
    {
        var builder = new StringBuilder();
        var procmonHits = hits.Where(x => x.IsProcmonEvidence && x.Found).ToArray();
        var otherHits = hits.Where(x => !x.IsProcmonEvidence).ToArray();

        if (procmonHits.Length > 0)
        {
            builder.AppendLine("PROCMON (ЖЁСТКОЕ ДОКАЗАТЕЛЬСТВО — ЧТЕНИЕ РЕЕСТРА УТИЛИТОЙ):");
            foreach (var hit in procmonHits.OrderByDescending(x => x.EvidenceRank))
            {
                builder.AppendLine(hit.DisplayLine);
            }

            builder.AppendLine();
        }

        builder.AppendLine(procmonHits.Length > 0
            ? "ПРОВЕРКА ИСТОЧНИКОВ WINDOWS (аудит + трассировка реестра):"
            : "ГДЕ ИСКАЛИ В WINDOWS (наш аудит + трассировка реестра):");

        if (isUsbDetector && procmonHits.Length == 0)
        {
            builder.AppendLine("• Типичные ветки USBDetector: Enum\\USB, USBSTOR, MountedDevices, MountPoints2.");
        }

        foreach (var hit in otherHits.OrderByDescending(x => x.Found).ThenBy(x => x.Title, StringComparer.OrdinalIgnoreCase))
        {
            builder.AppendLine(hit.DisplayLine);
        }

        if (isOtherTraces)
        {
            var allHits = hits.Where(x => x.Found).ToArray();
            var foundDirectUsb = allHits.Any(x =>
                x.Title.Contains(@"Enum\USB", StringComparison.OrdinalIgnoreCase)
                && !x.Title.Contains(@"Enum\USBSTOR", StringComparison.OrdinalIgnoreCase));
            var foundDirectUsbStor = allHits.Any(x =>
                x.Title.Contains(@"Enum\USBSTOR", StringComparison.OrdinalIgnoreCase));
            var foundDirect = foundDirectUsb || foundDirectUsbStor;
            var foundIndirect = allHits.Any(x => x.Title.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase)
                                                 || x.Title.Contains("MountPoints2", StringComparison.OrdinalIgnoreCase));
            var procmonDirect = procmonHits.Any(x => x.ResultText.Contains("прямой", StringComparison.OrdinalIgnoreCase));

            builder.AppendLine();
            if (procmonHits.Length > 0)
            {
                builder.AppendLine(procmonDirect
                    ? "Вывод Procmon: утилита читала прямой ключ Enum\\USB/USBSTOR — строка привязана к реальному следу реестра."
                    : "Вывод Procmon: утилита читала косвенный ключ (MountedDevices/MRU/MountPoints2) — это не доказательство физической флешки.");
            }
            else if (foundDirect)
            {
                builder.AppendLine("Вывод по источникам: есть прямой ключ реестра — строка, вероятно, из Enum\\USB/USBSTOR.");
            }
            else if (foundIndirect)
            {
                builder.AppendLine("Вывод по источникам: только косвенные ветки — не доказательство физической флешки.");
            }
            else
            {
                builder.AppendLine("Вывод по источникам: в типичных ветках след не найден — используйте Procmon для жёсткой фиксации источника.");
            }
        }

        return builder.ToString().TrimEnd();
    }

    private static bool PathsEquivalent(string left, string right)
    {
        var normalizedLeft = DevicePathNormalizer.NormalizeDeviceId(left).TrimEnd('\\');
        var normalizedRight = DevicePathNormalizer.NormalizeDeviceId(right).TrimEnd('\\');
        return normalizedLeft.Equals(normalizedRight, StringComparison.OrdinalIgnoreCase)
               || IsRegistryAncestor(normalizedLeft, normalizedRight)
               || IsRegistryAncestor(normalizedRight, normalizedLeft);
    }

    private static bool IsRegistryAncestor(string ancestor, string candidate) =>
        candidate.Length > ancestor.Length
        && candidate.StartsWith(ancestor, StringComparison.OrdinalIgnoreCase)
        && candidate[ancestor.Length] == '\\';

    private static void AppendAuditDeviceHits(
        ExternalUtilityIdentifierInfo identifier,
        AuditResult audit,
        List<ExternalUtilitySourceHit> hits)
    {
        var devices = audit.Devices.Where(device => MatchesDevice(identifier, device)).Take(5).ToArray();
        foreach (var device in devices)
        {
            hits.Add(new ExternalUtilitySourceHit
            {
                Title = device.Source.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase)
                    ? "MountedDevices (аудит)"
                    : device.Source.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
                        ? "Enum\\USBSTOR (аудит)"
                        : device.Source.Contains("USB", StringComparison.OrdinalIgnoreCase)
                            ? "Enum\\USB (аудит)"
                            : device.Source,
                RegistryPath = ToRegistryPath(device),
                Found = true,
                ResultText = $"{device.DisplayName}; {device.FirstConnectedText}",
                LikelyUsbDetectorSource = !device.Source.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase)
            });
        }
    }

    private static void AppendAuditEvidenceHits(
        ExternalUtilityIdentifierInfo identifier,
        AuditResult audit,
        List<ExternalUtilitySourceHit> hits)
    {
        var needles = BuildNeedles(identifier);
        foreach (var evidence in audit.Evidence)
        {
            var haystack = $"{evidence.Summary} {evidence.RawText} {evidence.DeviceHint}";
            if (!needles.Any(needle => haystack.Contains(needle, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var title = evidence.Source.Contains("MountPoints2", StringComparison.OrdinalIgnoreCase)
                ? "MountPoints2 (аудит)"
                : evidence.Source.Contains("MRU", StringComparison.OrdinalIgnoreCase)
                    ? "MRU (аудит)"
                    : evidence.Source;

            if (hits.Any(x => x.Title.Equals(title, StringComparison.OrdinalIgnoreCase) && x.Found))
            {
                continue;
            }

            hits.Add(new ExternalUtilitySourceHit
            {
                Title = title,
                RegistryPath = evidence.RawText.Length > 120 ? evidence.Summary : evidence.RawText,
                Found = true,
                ResultText = ReportText.ForDisplay(evidence.Summary, 120),
                LikelyUsbDetectorSource = title.Contains("MountPoints", StringComparison.OrdinalIgnoreCase)
                                          || title.Contains("MRU", StringComparison.OrdinalIgnoreCase)
            });
        }
    }

    private static bool MatchesDevice(ExternalUtilityIdentifierInfo identifier, UsbDeviceRecord device)
    {
        if (!identifier.HasVid)
        {
            return false;
        }

        if (!device.Vid.Equals(identifier.Vid, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (identifier.HasFullPair)
        {
            return device.Pid.Equals(identifier.Pid, StringComparison.OrdinalIgnoreCase)
                   || string.IsNullOrWhiteSpace(device.Pid);
        }

        return true;
    }

    private static string ToRegistryPath(UsbDeviceRecord device)
    {
        if (device.DeviceInstanceId.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase)
            || device.DeviceInstanceId.StartsWith(@"HKU\", StringComparison.OrdinalIgnoreCase))
        {
            return device.DeviceInstanceId;
        }

        if (device.Source.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase))
        {
            return @"HKLM\SYSTEM\MountedDevices";
        }

        if (device.DeviceInstanceId.Contains('\\'))
        {
            return $@"HKLM\SYSTEM\CurrentControlSet\Enum\{device.DeviceInstanceId}";
        }

        return device.DeviceInstanceId;
    }

    private static string[] BuildNeedles(ExternalUtilityIdentifierInfo identifier)
    {
        var needles = new List<string> { identifier.Vid! };
        if (identifier.HasFullPair)
        {
            needles.Add($"VID_{identifier.Vid}&PID_{identifier.Pid}");
            needles.Add($"{identifier.Vid}/{identifier.Pid}");
        }
        else
        {
            needles.Add($"VID_{identifier.Vid}");
        }

        return needles.ToArray();
    }
}
