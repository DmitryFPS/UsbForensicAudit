using System.Buffers.Binary;
using System.IO;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace UsbForensicAudit;

public sealed class UserArtifactCollector : IEvidenceCollector
{
    private const int MaxRegistryRecordsPerSid = 4000;
    private const int MaxFilesPerProfile = 5000;

    public string ProgressMessage => "Структурный сбор HKU, Shellbags, LNK, Jump Lists и Recycle Bin...";
    public bool ShouldRun => true;

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings)
    {
        var evidence = new List<EvidenceRecord>();
        var profiles = ResolveProfiles(warnings);
        CollectLoadedUserRegistry(profiles, evidence, warnings);
        CollectProfileArtifacts(profiles, evidence, warnings);
        return evidence;
    }

    internal static IReadOnlyDictionary<string, UserProfileIdentity> ResolveProfiles(List<string> warnings)
    {
        var result = new Dictionary<string, UserProfileIdentity>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (root is not null)
            {
                foreach (var sid in root.GetSubKeyNames().Take(1024))
                {
                    using var key = root.OpenSubKey(sid);
                    var path = Environment.ExpandEnvironmentVariables(key?.GetValue("ProfileImagePath") as string ?? "");
                    var name = ResolveAccountName(sid, Path.GetFileName(path));
                    result[sid] = new UserProfileIdentity(sid, name, path);
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"ProfileList mapping недоступен: {ex.Message}");
        }
        return result;
    }

    internal static string ResolveAccountName(string sid, string fallback)
    {
        try
        {
            var translated = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
            return string.IsNullOrWhiteSpace(translated) ? fallback : translated;
        }
        catch
        {
            return fallback;
        }
    }

    private static void CollectLoadedUserRegistry(
        IReadOnlyDictionary<string, UserProfileIdentity> profiles,
        List<EvidenceRecord> evidence,
        List<string> warnings)
    {
        try
        {
            using var users = Registry.Users;
            foreach (var sid in users.GetSubKeyNames()
                         .Where(x => x.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase)
                                     && !x.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)))
            {
                var profile = profiles.TryGetValue(sid, out var found)
                    ? found
                    : new UserProfileIdentity(sid, ResolveAccountName(sid, sid), "");
                var before = evidence.Count;
                CollectMountPoints(users, sid, profile, evidence);
                CollectMruTree(users, sid, profile,
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", "RecentDocs", evidence);
                CollectMruTree(users, sid, profile,
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU", "OpenSavePidlMRU", evidence);
                CollectMruTree(users, sid, profile,
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU", "LastVisitedPidlMRU", evidence);
                CollectStringRegistry(users, sid, profile,
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", "TypedPaths", evidence);
                CollectMruTree(users, sid, profile,
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery", "WordWheelQuery", evidence);
                CollectUserAssist(users, sid, profile, evidence);
                CollectShellBags(users, sid + "_Classes", profile, "Live HKU SID_Classes", evidence);
                if (evidence.Count - before >= MaxRegistryRecordsPerSid)
                {
                    warnings.Add($"User registry {sid}: достигнут лимит {MaxRegistryRecordsPerSid} записей.");
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения HKU пользовательских артефактов: {ex.Message}");
        }
    }

    internal static void CollectMountedNtUser(
        RegistryKey users, string mountName, UserProfileIdentity profile, string sourcePrefix,
        List<EvidenceRecord> evidence)
    {
        var start = evidence.Count;
        CollectMountPoints(users, mountName, profile, evidence);
        CollectMruTree(users, mountName, profile,
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", "RecentDocs", evidence);
        CollectMruTree(users, mountName, profile,
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU", "OpenSavePidlMRU", evidence);
        CollectMruTree(users, mountName, profile,
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU", "LastVisitedPidlMRU", evidence);
        CollectStringRegistry(users, mountName, profile,
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", "TypedPaths", evidence);
        CollectMruTree(users, mountName, profile,
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery", "WordWheelQuery", evidence);
        CollectUserAssist(users, mountName, profile, evidence);
        foreach (var item in evidence.Skip(start))
        {
            item.Source = $"{sourcePrefix} {item.Source}";
        }
    }

    private static void CollectMountPoints(
        RegistryKey users, string sid, UserProfileIdentity profile, List<EvidenceRecord> evidence)
    {
        const string relative = @"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2";
        using var key = users.OpenSubKey($@"{sid}\{relative}");
        if (key is null) return;
        foreach (var name in key.GetSubKeyNames().Take(MaxRegistryRecordsPerSid))
        {
            if (!ForensicArtifactParsers.IsUsbOrVolumeMarker(name)
                && !name.StartsWith("##", StringComparison.Ordinal)
                && !name.StartsWith("{", StringComparison.Ordinal))
            {
                continue;
            }
            using var child = key.OpenSubKey(name);
            AddDeduplicated(evidence, NewRegistryEvidence(
                "HKU MountPoints2", profile, $@"HKU\{sid}\{relative}\{name}",
                name, "Explorer mount-point memory; does not establish a connection time.",
                child is null ? null : RegistryKeyTimestamps.GetLastWriteUtc(child), "Corroborating", "Medium"));
        }
    }

    private static void CollectMruTree(
        RegistryKey users,
        string sid,
        UserProfileIdentity profile,
        string relative,
        string artifact,
        List<EvidenceRecord> evidence)
    {
        using var root = users.OpenSubKey($@"{sid}\{relative}");
        if (root is null) return;
        var count = 0;
        WalkMru(root, $@"HKU\{sid}\{relative}", profile, artifact, evidence, ref count, 0);
    }

    private static void WalkMru(
        RegistryKey key,
        string path,
        UserProfileIdentity profile,
        string artifact,
        List<EvidenceRecord> evidence,
        ref int count,
        int depth)
    {
        if (depth > 12 || count >= MaxRegistryRecordsPerSid) return;
        var order = ForensicArtifactParsers.ParseMruListEx(key.GetValue("MRUListEx"));
        var names = order.Select(x => x.ToString())
            .Concat(key.GetValueNames().Where(x => x != "MRUListEx"))
            .Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var name in names)
        {
            if (count >= MaxRegistryRecordsPerSid) break;
            var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            var parsed = value is byte[] bytes ? ForensicArtifactParsers.ParsePidl(bytes) : null;
            var text = parsed?.BestPath ?? ValueText(value);
            if (!ForensicArtifactParsers.IsUsbOrVolumeMarker(text) && !ArtifactStringExtractor.LooksInteresting(text))
            {
                continue;
            }
            var rank = FindIndex(order, int.TryParse(name, out var number) ? number : -1);
            AddDeduplicated(evidence, NewRegistryEvidence(
                $"HKU {artifact}", profile, $"{path}\\{name}", text,
                $"Structured MRU/PIDL artifact; MRU rank={(rank < 0 ? "unknown" : rank)}. It is user activity, not a USB connection event.",
                RegistryKeyTimestamps.GetLastWriteUtc(key), "Indirect", "Medium",
                parsed is null ? ValueText(value) : string.Join("; ", parsed.PathFragments)));
            count++;
        }

        foreach (var childName in key.GetSubKeyNames())
        {
            using var child = key.OpenSubKey(childName);
            if (child is not null)
            {
                WalkMru(child, $"{path}\\{childName}", profile, artifact, evidence, ref count, depth + 1);
            }
        }
    }

    private static void CollectStringRegistry(
        RegistryKey users, string sid, UserProfileIdentity profile, string relative, string artifact,
        List<EvidenceRecord> evidence)
    {
        using var key = users.OpenSubKey($@"{sid}\{relative}");
        if (key is null) return;
        foreach (var name in key.GetValueNames().Take(1000))
        {
            var text = ValueText(key.GetValue(name));
            if (!ForensicArtifactParsers.IsUsbOrVolumeMarker(text) && !ArtifactStringExtractor.LooksInteresting(text)) continue;
            AddDeduplicated(evidence, NewRegistryEvidence(
                $"HKU {artifact}", profile, $@"HKU\{sid}\{relative}\{name}", text,
                "User-entered path; indirect evidence only.", RegistryKeyTimestamps.GetLastWriteUtc(key), "Indirect", "Medium"));
        }
    }

    private static void CollectUserAssist(
        RegistryKey users, string sid, UserProfileIdentity profile, List<EvidenceRecord> evidence)
    {
        const string relative = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        using var root = users.OpenSubKey($@"{sid}\{relative}");
        if (root is null) return;
        foreach (var guid in root.GetSubKeyNames().Take(100))
        {
            using var count = root.OpenSubKey($@"{guid}\Count");
            if (count is null) continue;
            foreach (var encoded in count.GetValueNames().Take(5000))
            {
                var decoded = Rot13(encoded);
                if (!ArtifactStringExtractor.LooksInteresting(decoded) && !CleanerToolCatalog.LooksLikeCleaner(decoded)) continue;
                AddDeduplicated(evidence, NewRegistryEvidence(
                    "HKU UserAssist", profile, $@"HKU\{sid}\{relative}\{guid}\Count\{encoded}", decoded,
                    "UserAssist supports application interaction, but alone does not prove execution or USB connection.",
                    RegistryKeyTimestamps.GetLastWriteUtc(count), "Corroborating", "Medium",
                    $"DecodedName={decoded}; BinaryLength={(count.GetValue(encoded) as byte[])?.Length ?? 0}"));
            }
        }
    }

    internal static void CollectShellBags(
        RegistryKey users, string sidClasses, UserProfileIdentity profile, string sourcePrefix,
        List<EvidenceRecord> evidence)
    {
        const string relative = @"Local Settings\Software\Microsoft\Windows\Shell\BagMRU";
        using var root = users.OpenSubKey($@"{sidClasses}\{relative}");
        if (root is null) return;
        var count = 0;
        WalkShellBags(root, $@"HKU\{sidClasses}\{relative}", "", profile, sourcePrefix, evidence, ref count, 0);
    }

    private static void WalkShellBags(
        RegistryKey key, string registryPath, string parentPath, UserProfileIdentity profile,
        string sourcePrefix, List<EvidenceRecord> evidence, ref int count, int depth)
    {
        if (depth > 16 || count >= MaxRegistryRecordsPerSid) return;
        var slot = TryInt(key.GetValue("NodeSlot"));
        foreach (var name in key.GetValueNames().Where(x => int.TryParse(x, out _)))
        {
            var parsed = ForensicArtifactParsers.ParseShellBagNode(key.GetValue(name) as byte[], parentPath, slot);
            if (!parsed.IsUsbRelevant) continue;
            AddDeduplicated(evidence, NewRegistryEvidence(
                $"{sourcePrefix} Shellbags", profile, $"{registryPath}\\{name}", parsed.Path,
                $"Structured BagMRU node; slot={parsed.Slot?.ToString() ?? "unknown"}. Filtered by USB/volume/WPD marker; not a connection event.",
                RegistryKeyTimestamps.GetLastWriteUtc(key), "Indirect", "Medium"));
            count++;
        }
        foreach (var childName in key.GetSubKeyNames())
        {
            using var child = key.OpenSubKey(childName);
            if (child is null) continue;
            var childNode = ForensicArtifactParsers.ParseShellBagNode(key.GetValue(childName) as byte[], parentPath, slot);
            WalkShellBags(child, $"{registryPath}\\{childName}",
                string.IsNullOrWhiteSpace(childNode.Path) ? parentPath : childNode.Path,
                profile, sourcePrefix, evidence, ref count, depth + 1);
        }
    }

    private static void CollectProfileArtifacts(
        IReadOnlyDictionary<string, UserProfileIdentity> profiles,
        List<EvidenceRecord> evidence,
        List<string> warnings)
    {
        foreach (var profile in profiles.Values.Where(x => Directory.Exists(x.ProfilePath)).Take(256))
        {
            var roots = new[]
            {
                Path.Combine(profile.ProfilePath, "AppData", "Roaming", "Microsoft", "Windows", "Recent"),
                Path.Combine(profile.ProfilePath, "Desktop"),
                Path.Combine(profile.ProfilePath, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu"),
                Path.Combine(profile.ProfilePath, "AppData", "Roaming", "Microsoft", "Windows", "SendTo")
            };
            foreach (var root in roots) CollectLinks(root, profile, evidence, warnings);
            CollectJumpLists(profile, evidence, warnings);
            CollectRecycleBin(profile, evidence, warnings);
        }
    }

    private static void CollectLinks(
        string root, UserProfileIdentity profile, List<EvidenceRecord> evidence, List<string> warnings)
    {
        if (!Directory.Exists(root)) return;
        try
        {
            var paths = Directory.EnumerateFiles(root, "*.lnk", SearchOption.AllDirectories)
                .Take(MaxFilesPerProfile + 1)
                .ToArray();
            if (paths.Length > MaxFilesPerProfile)
            {
                warnings.Add($"LNK collection {profile.ResolvedUserName}/{root}: достигнут лимит {MaxFilesPerProfile} файлов.");
            }
            foreach (var path in paths.Take(MaxFilesPerProfile))
            {
                var link = ShellLinkParser.TryParse(path);
                if (link is null) continue;
                var target = link.BestTarget;
                if (!ForensicArtifactParsers.IsUsbOrVolumeMarker(target) && !ArtifactStringExtractor.LooksInteresting(target)) continue;
                AddDeduplicated(evidence, NewFileEvidence(
                    "User LNK Parsed", profile, path, target,
                    "Structurally parsed Shell Link. Target timestamps describe the target/link metadata, not USB connection time.",
                    link.WriteTimeUtc ?? File.GetLastWriteTimeUtc(path), "Indirect", "High",
                    $"VolumeSerial={link.VolumeSerialNumber}; VolumeLabel={link.VolumeLabel}; Target={target}"));
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"LNK collection {profile.ResolvedUserName}/{root}: {ex.Message}");
        }
    }

    private static void CollectJumpLists(
        UserProfileIdentity profile, List<EvidenceRecord> evidence, List<string> warnings)
    {
        var recent = Path.Combine(profile.ProfilePath, "AppData", "Roaming", "Microsoft", "Windows", "Recent");
        foreach (var (directory, automatic) in new[]
                 {
                     (Path.Combine(recent, "AutomaticDestinations"), true),
                     (Path.Combine(recent, "CustomDestinations"), false)
                 })
        {
            if (!Directory.Exists(directory)) continue;
            try
            {
                const int maxJumpLists = 2000;
                var paths = Directory.EnumerateFiles(directory).Take(maxJumpLists + 1).ToArray();
                if (paths.Length > maxJumpLists)
                {
                    warnings.Add($"Jump Lists {profile.ResolvedUserName}/{directory}: достигнут лимит {maxJumpLists} файлов.");
                }
                foreach (var path in paths.Take(maxJumpLists))
                {
                    var appId = Path.GetFileName(path).Split('.').FirstOrDefault() ?? "";
                    var bytes = File.ReadAllBytes(path);
                    var entries = automatic
                        ? ForensicArtifactParsers.ParseAutomaticJumpList(bytes, appId)
                        : ForensicArtifactParsers.ParseCustomJumpList(bytes, appId);
                    foreach (var entry in entries)
                    {
                        var target = entry.Link.BestTarget;
                        if (!ForensicArtifactParsers.IsUsbOrVolumeMarker(target)
                            && !ArtifactStringExtractor.LooksInteresting(target)) continue;
                        AddDeduplicated(evidence, NewFileEvidence(
                            automatic ? "JumpList AutomaticDestinations Parsed" : "JumpList CustomDestinations Parsed",
                            profile, path, target,
                            "Embedded LNK parsed from Jump List; user activity only, not a USB connection event.",
                            entry.EntryTimestampUtc ?? entry.Link.WriteTimeUtc ?? File.GetLastWriteTimeUtc(path),
                            "Indirect", "High",
                            $"AppID={entry.AppId}; Stream={entry.StreamName}; Target={target}; VolumeSerial={entry.Link.VolumeSerialNumber}"));
                    }
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Jump Lists {profile.ResolvedUserName}: {ex.Message}");
            }
        }
    }

    private static void CollectRecycleBin(
        UserProfileIdentity profile, List<EvidenceRecord> evidence, List<string> warnings)
    {
        const int maxRecycleMetadata = 5000;
        string[] driveRoots;
        try
        {
            driveRoots = DriveInfo.GetDrives()
                .Where(x => x.IsReady)
                .Select(x => x.RootDirectory.FullName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception ex)
        {
            warnings.Add($"Recycle Bin drive enumeration: {ex.Message}");
            return;
        }

        var paths = new List<string>();
        foreach (var driveRoot in driveRoots)
        {
            var root = Path.Combine(driveRoot, "$Recycle.Bin", profile.Sid);
            if (!Directory.Exists(root)) continue;
            try
            {
                paths.AddRange(Directory.EnumerateFiles(root, "$I*", SearchOption.AllDirectories)
                    .Take(maxRecycleMetadata + 1 - Math.Min(paths.Count, maxRecycleMetadata)));
            }
            catch (Exception ex)
            {
                warnings.Add($"Recycle Bin {profile.ResolvedUserName}/{driveRoot}: {ex.Message}");
            }
            if (paths.Count > maxRecycleMetadata) break;
        }

        if (paths.Count > maxRecycleMetadata)
        {
            warnings.Add($"Recycle Bin {profile.ResolvedUserName}: достигнут лимит {maxRecycleMetadata} файлов.");
        }
        foreach (var path in paths.Take(maxRecycleMetadata))
        {
            try
            {
                var parsed = ParseRecycleMetadata(File.ReadAllBytes(path));
                if (parsed is null || (!ArtifactStringExtractor.LooksInteresting(parsed.Value.OriginalPath)
                                       && !ForensicArtifactParsers.IsUsbOrVolumeMarker(parsed.Value.OriginalPath))) continue;
                AddDeduplicated(evidence, NewFileEvidence(
                    "Recycle Bin $I", profile, path, parsed.Value.OriginalPath,
                    "Recycle Bin metadata: deletion event for a removable-path candidate; indirect evidence.",
                    parsed.Value.DeletedUtc, "Indirect", "High",
                    $"OriginalPath={parsed.Value.OriginalPath}; OriginalSize={parsed.Value.Size}"));
            }
            catch (Exception ex)
            {
                warnings.Add($"Recycle Bin metadata {path}: {ex.Message}");
            }
        }
    }

    internal static (string OriginalPath, long Size, DateTimeOffset DeletedUtc)? ParseRecycleMetadata(byte[] data)
    {
        if (data.Length < 24) return null;
        var version = BinaryPrimitives.ReadInt64LittleEndian(data);
        var size = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(8, 8));
        DateTimeOffset deleted;
        try { deleted = DateTimeOffset.FromFileTime(BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(16, 8))).ToUniversalTime(); }
        catch { return null; }
        string original;
        if (version == 2 && data.Length >= 28)
        {
            var chars = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(24, 4));
            if (chars <= 0 || chars > 32_767 || 28 + chars * 2 > data.Length) return null;
            original = Encoding.Unicode.GetString(data, 28, chars * 2).TrimEnd('\0');
        }
        else if (version == 1)
        {
            original = Encoding.Unicode.GetString(data, 24, data.Length - 24).TrimEnd('\0');
        }
        else return null;
        return (original, size, deleted);
    }

    private static EvidenceRecord NewRegistryEvidence(
        string source, UserProfileIdentity profile, string provenance, string hint, string explanation,
        DateTimeOffset? lastWrite, string strength, string confidence, string raw = "") => new()
        {
            TimestampUtc = lastWrite ?? DateTimeOffset.UtcNow,
            RegistryLastWriteUtc = lastWrite,
            Source = source,
            Provider = "Windows Registry",
            Channel = "User artifact",
            SourceRecord = provenance,
            EvidenceCategory = "User activity",
            UserExplanation = explanation,
            DeviceHint = hint,
            Summary = $"{source}: {hint}",
            RawText = raw,
            Provenance = provenance,
            EvidenceStrength = strength,
            Confidence = confidence,
            UserSid = profile.Sid,
            ResolvedUserName = profile.ResolvedUserName,
            CanEstablishConnectionDate = false
        };

    private static EvidenceRecord NewFileEvidence(
        string source, UserProfileIdentity profile, string path, string hint, string explanation,
        DateTimeOffset timestamp, string strength, string confidence, string raw) => new()
        {
            TimestampUtc = timestamp,
            Source = source,
            Provider = "Profile filesystem",
            Channel = "User artifact",
            SourceFile = path,
            SourceRecord = path,
            EvidenceCategory = "User activity",
            UserExplanation = explanation,
            DeviceHint = hint,
            Summary = $"{source}: {hint}",
            RawText = raw,
            Provenance = $"Read-only source path: {path}",
            EvidenceStrength = strength,
            Confidence = confidence,
            UserSid = profile.Sid,
            ResolvedUserName = profile.ResolvedUserName,
            CanEstablishConnectionDate = false
        };

    internal static void AddDeduplicated(List<EvidenceRecord> evidence, EvidenceRecord record)
    {
        var key = ArtifactDeduplicator.Key(record);
        if (!evidence.Any(x => ArtifactDeduplicator.Key(x).Equals(key, StringComparison.OrdinalIgnoreCase)))
        {
            evidence.Add(record);
        }
    }

    private static string ValueText(object? value) => value switch
    {
        byte[] bytes => ForensicArtifactParsers.ParsePidl(bytes).BestPath,
        string text => text,
        string[] values => string.Join("; ", values),
        _ => value?.ToString() ?? ""
    };

    private static int? TryInt(object? value)
    {
        try { return value is null ? null : Convert.ToInt32(value); }
        catch { return null; }
    }

    private static int FindIndex(IReadOnlyList<int> values, int value)
    {
        for (var i = 0; i < values.Count; i++)
        {
            if (values[i] == value) return i;
        }
        return -1;
    }

    private static string Rot13(string value) => new(value.Select(c =>
        c is >= 'a' and <= 'z' ? (char)('a' + (c - 'a' + 13) % 26)
        : c is >= 'A' and <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());
}

internal sealed record UserProfileIdentity(string Sid, string ResolvedUserName, string ProfilePath);

internal static class ArtifactDeduplicator
{
    internal static string Key(EvidenceRecord record) => string.Join("|",
        record.UserSid.Trim().ToUpperInvariant(),
        record.Source.Replace("Offline ", "", StringComparison.OrdinalIgnoreCase).Trim().ToUpperInvariant(),
        record.DeviceHint.Trim().ToUpperInvariant(),
        record.SourceRecord.Split('\\').LastOrDefault()?.ToUpperInvariant() ?? "");
}
