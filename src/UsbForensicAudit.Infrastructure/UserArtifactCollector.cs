using Microsoft.Win32;
using System.IO;

namespace UsbForensicAudit;

public sealed class UserArtifactCollector : IEvidenceCollector
{
    public string ProgressMessage => "Сбор пользовательских артефактов: HKU, Recent, LNK, Jump Lists...";

    public bool ShouldRun => true;

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings)
    {
        var evidence = new List<EvidenceRecord>();
        CollectLoadedUserRegistry(evidence, warnings);
        CollectProfileFileArtifacts(evidence, warnings);
        return evidence;
    }

    private static void CollectLoadedUserRegistry(List<EvidenceRecord> evidence, List<string> warnings)
    {
        try
        {
            using var users = Registry.Users;
            foreach (var sid in users.GetSubKeyNames().Where(x => x.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase) && !x.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)))
            {
                CollectUserKey(users, sid, @"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2", "HKU MountPoints2", evidence);
                CollectUserKey(users, sid, @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", "HKU RecentDocs", evidence);
                CollectUserKey(users, sid, @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU", "HKU OpenSavePidlMRU", evidence);
                CollectUserKey(users, sid, @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU", "HKU LastVisitedPidlMRU", evidence);
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения HKU пользовательских артефактов: {ex.Message}");
        }
    }

    private static void CollectUserKey(RegistryKey users, string sid, string relativePath, string source, List<EvidenceRecord> evidence)
    {
        using var key = users.OpenSubKey($@"{sid}\{relativePath}");
        if (key is null)
        {
            return;
        }

        foreach (var subName in key.GetSubKeyNames())
        {
            if (ArtifactStringExtractor.LooksInteresting(subName) || subName.Contains("Volume", StringComparison.OrdinalIgnoreCase))
            {
                evidence.Add(new EvidenceRecord
                {
                    Source = source,
                    EventId = sid,
                    DeviceHint = subName,
                    Summary = $@"{sid}\{relativePath}\{subName}",
                    RawText = $@"HKU\{sid}\{relativePath}\{subName}"
                });
            }
        }

        foreach (var valueName in key.GetValueNames())
        {
            var value = key.GetValue(valueName);
            var text = value switch
            {
                byte[] bytes => Convert.ToHexString(bytes.Take(128).ToArray()),
                string s => s,
                string[] strings => string.Join("; ", strings),
                _ => value?.ToString() ?? ""
            };

            if (ArtifactStringExtractor.LooksInteresting(valueName) || ArtifactStringExtractor.LooksInteresting(text))
            {
                evidence.Add(new EvidenceRecord
                {
                    Source = source,
                    EventId = sid,
                    DeviceHint = valueName,
                    Summary = $@"{sid}\{relativePath}: {valueName}",
                    RawText = text
                });
            }
        }
    }

    private static void CollectProfileFileArtifacts(List<EvidenceRecord> evidence, List<string> warnings)
    {
        var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? @"C:\";
        var usersRoot = Path.Combine(systemDrive, "Users");
        if (!Directory.Exists(usersRoot))
        {
            warnings.Add($"Папка профилей не найдена: {usersRoot}");
            return;
        }

        foreach (var profile in Directory.EnumerateDirectories(usersRoot))
        {
            var userName = Path.GetFileName(profile);
            if (IsSystemProfile(userName))
            {
                continue;
            }

            CollectRecentLinks(profile, userName, evidence, warnings);
            CollectJumpLists(profile, userName, evidence, warnings);
            AddHivePresence(profile, userName, evidence);
        }
    }

    private static void CollectRecentLinks(string profile, string userName, List<EvidenceRecord> evidence, List<string> warnings)
    {
        var recent = Path.Combine(profile, "AppData", "Roaming", "Microsoft", "Windows", "Recent");
        if (!Directory.Exists(recent))
        {
            return;
        }

        try
        {
            foreach (var lnk in Directory.EnumerateFiles(recent, "*.lnk", SearchOption.AllDirectories).Take(2000))
            {
                var hints = ArtifactStringExtractor.ExtractInterestingStrings(lnk, maxBytes: 256_000, maxResults: 12);
                var parsed = ShellLinkParser.TryParse(lnk);
                var parsedHints = BuildLinkHints(parsed);

                if (hints.Count == 0 && parsedHints.Count == 0)
                {
                    continue;
                }

                var info = new FileInfo(lnk);
                evidence.Add(new EvidenceRecord
                {
                    TimestampUtc = parsed?.WriteTimeUtc ?? info.LastWriteTimeUtc,
                    Source = parsedHints.Count > 0 ? "User Recent/LNK Parsed" : "User Recent/LNK",
                    EventId = userName,
                    DeviceHint = BuildDisplayHint(parsed, parsedHints, hints),
                    Summary = BuildLinkSummary(lnk, parsed),
                    RawText = BuildLinkRawText(lnk, parsed, hints)
                });
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения Recent/LNK для {userName}: {ex.Message}");
        }
    }

    private static IReadOnlyList<string> BuildLinkHints(ShellLinkInfo? parsed)
    {
        if (parsed is null)
        {
            return [];
        }

        var hints = new List<string>();
        AddIfInteresting(parsed.BestTarget, hints);
        AddIfInteresting(parsed.LocalBasePath, hints);
        AddIfInteresting(parsed.CommonPathSuffix, hints);

        if (!string.IsNullOrWhiteSpace(parsed.VolumeSerialNumber))
        {
            hints.Add($"VolumeSerial={parsed.VolumeSerialNumber}");
        }

        if (!string.IsNullOrWhiteSpace(parsed.VolumeLabel))
        {
            hints.Add($"VolumeLabel={parsed.VolumeLabel}");
        }

        return hints;
    }

    private static string BuildLinkRawText(string linkPath, ShellLinkInfo? parsed, IReadOnlyList<string> stringHints)
    {
        if (parsed is null)
        {
            return string.Join(Environment.NewLine, stringHints);
        }

        return string.Join(Environment.NewLine, new[]
        {
            $"LinkPath={linkPath}",
            $"Target={parsed.BestTarget}",
            $"LocalBasePath={parsed.LocalBasePath}",
            $"CommonPathSuffix={parsed.CommonPathSuffix}",
            $"VolumeLabel={parsed.VolumeLabel}",
            $"VolumeSerial={parsed.VolumeSerialNumber}",
            $"CreatedUtc={parsed.CreationTimeUtc:O}",
            $"AccessedUtc={parsed.AccessTimeUtc:O}",
            $"WrittenUtc={parsed.WriteTimeUtc:O}",
            $"StringHints={string.Join("; ", stringHints)}"
        });
    }

    private static string BuildDisplayHint(ShellLinkInfo? parsed, IReadOnlyList<string> parsedHints, IReadOnlyList<string> rawHints)
    {
        if (parsed is not null)
        {
            var target = TextSanitizer.NormalizeDisplay(parsed.BestTarget, 500);
            if (!string.IsNullOrWhiteSpace(target))
            {
                return target;
            }
        }

        var source = parsedHints.Count > 0 ? parsedHints : rawHints;
        var cleaned = source
            .Select(value => TextSanitizer.NormalizeDisplay(value, 220))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(4)
            .ToArray();

        return string.Join("; ", cleaned);
    }

    private static string BuildLinkSummary(string linkPath, ShellLinkInfo? parsed)
    {
        if (parsed is not null)
        {
            var target = TextSanitizer.NormalizeDisplay(parsed.BestTarget, 500);
            if (!string.IsNullOrWhiteSpace(target))
            {
                return $"LNK target: {target}";
            }
        }

        return $"LNK содержит USB/Volume/drive индикаторы: {Path.GetFileName(linkPath)}";
    }

    private static void AddIfInteresting(string value, List<string> hints)
    {
        if (!string.IsNullOrWhiteSpace(value)
            && ArtifactStringExtractor.LooksInteresting(value)
            && TextSanitizer.IsReadableForDisplay(value))
        {
            hints.Add(value);
        }
    }

    private static void CollectJumpLists(string profile, string userName, List<EvidenceRecord> evidence, List<string> warnings)
    {
        var automatic = Path.Combine(profile, "AppData", "Roaming", "Microsoft", "Windows", "Recent", "AutomaticDestinations");
        var custom = Path.Combine(profile, "AppData", "Roaming", "Microsoft", "Windows", "Recent", "CustomDestinations");

        foreach (var directory in new[] { automatic, custom })
        {
            if (!Directory.Exists(directory))
            {
                continue;
            }

            try
            {
                foreach (var file in Directory.EnumerateFiles(directory).Take(1000))
                {
                    var hints = ArtifactStringExtractor.ExtractInterestingStrings(file, maxBytes: 1_000_000, maxResults: 12);
                    if (hints.Count == 0)
                    {
                        continue;
                    }

                    var info = new FileInfo(file);
                    evidence.Add(new EvidenceRecord
                    {
                        TimestampUtc = info.LastWriteTimeUtc,
                        Source = directory.EndsWith("AutomaticDestinations", StringComparison.OrdinalIgnoreCase) ? "JumpList AutomaticDestinations" : "JumpList CustomDestinations",
                        EventId = userName,
                        DeviceHint = BuildDisplayHint(null, [], hints),
                        Summary = $"Jump List содержит USB/Volume/drive индикаторы: {file}",
                        RawText = string.Join(Environment.NewLine, hints)
                    });
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Ошибка чтения Jump Lists для {userName}: {ex.Message}");
            }
        }
    }

    private static void AddHivePresence(string profile, string userName, List<EvidenceRecord> evidence)
    {
        foreach (var hive in new[] { "NTUSER.DAT", Path.Combine("AppData", "Local", "Microsoft", "Windows", "UsrClass.dat") })
        {
            var path = Path.Combine(profile, hive);
            if (!File.Exists(path))
            {
                continue;
            }

            var info = new FileInfo(path);
            evidence.Add(new EvidenceRecord
            {
                TimestampUtc = info.LastWriteTimeUtc,
                Source = "User Hive Presence",
                EventId = userName,
                Summary = $"Найден пользовательский hive: {path}",
                RawText = $"Created={info.CreationTimeUtc:O}; Modified={info.LastWriteTimeUtc:O}; Size={info.Length:N0}"
            });
        }
    }

    private static bool IsSystemProfile(string userName)
    {
        return userName.Equals("All Users", StringComparison.OrdinalIgnoreCase)
               || userName.Equals("Default", StringComparison.OrdinalIgnoreCase)
               || userName.Equals("Default User", StringComparison.OrdinalIgnoreCase)
               || userName.Equals("Public", StringComparison.OrdinalIgnoreCase);
    }
}
