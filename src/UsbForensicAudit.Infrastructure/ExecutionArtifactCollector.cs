using System.Diagnostics;
using System.IO;
using System.Text;
using Microsoft.Win32;

namespace UsbForensicAudit;

public sealed class ExecutionArtifactCollector : IEvidenceCollector
{
    public string ProgressMessage => "Структурный сбор Prefetch, Amcache, Shimcache, PCA и BAM/DAM...";
    public bool ShouldRun => true;

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings)
    {
        var evidence = new List<EvidenceRecord>();
        CollectPrefetch(evidence, warnings);
        CollectAmcache(evidence, warnings);
        CollectShimcache(evidence, warnings);
        CollectPca(evidence, warnings);
        CollectBamDam(evidence, warnings);
        return evidence;
    }

    private static void CollectPrefetch(List<EvidenceRecord> evidence, List<string> warnings)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(root))
        {
            warnings.Add($"Prefetch недоступен или отключен: {root}");
            return;
        }
        try
        {
            const int maxPrefetchFiles = 5000;
            var paths = Directory.EnumerateFiles(root, "*.pf").Take(maxPrefetchFiles + 1).ToArray();
            if (paths.Length > maxPrefetchFiles)
            {
                warnings.Add($"Prefetch: достигнут лимит {maxPrefetchFiles} файлов.");
            }
            foreach (var path in paths.Take(maxPrefetchFiles))
            {
                var fileName = Path.GetFileName(path);
                var hints = ArtifactStringExtractor.ExtractInterestingStrings(path, 800_000, 20);
                var cleaner = CleanerToolCatalog.MatchTrackedUtility(fileName)
                              ?? CleanerToolCatalog.MatchTrackedUtility(string.Join(" ", hints));
                if (cleaner is null && hints.Count == 0) continue;

                var isReadOnly = false;
                try
                {
                    isReadOnly = (File.GetAttributes(path) & FileAttributes.ReadOnly) != 0;
                }
                catch
                {
                    // Атрибуты Prefetch не критичны для основного сценария.
                }

                evidence.Add(new EvidenceRecord
                {
                    TimestampUtc = File.GetLastWriteTimeUtc(path),
                    Source = "Prefetch",
                    Provider = "Windows Prefetch",
                    Channel = "Execution",
                    SourceFile = path,
                    EventId = cleaner is null ? "REMOVABLE_PATH" : isReadOnly ? "CLEANER_PREFETCH_TAMPER" : "CLEANER_EXECUTION",
                    EvidenceCategory = "Execution",
                    EvidenceStrength = ClassifyPrefetchEvidenceStrength(cleaner is not null),
                    Confidence = cleaner is null ? "Medium" : "High",
                    DeviceHint = string.Join("; ", hints),
                    Summary = cleaner is null
                        ? $"Prefetch removable-path correlation: {fileName}"
                        : isReadOnly
                            ? $"Prefetch (read-only): {CleanerToolCatalog.DisplayName(cleaner)}"
                            : $"Prefetch: {CleanerToolCatalog.DisplayName(cleaner)}",
                    UserExplanation = isReadOnly
                        ? "Prefetch file is marked read-only. Some anti-forensic tools do this after wiping or blocking further updates."
                        : "Prefetch strongly supports program execution; embedded paths do not establish USB connection time.",
                    Provenance = $"Read-only Prefetch: {path}",
                    RawText = $"Executable={fileName}; ReadOnly={isReadOnly}; Hints={string.Join("; ", hints)}",
                    CanEstablishConnectionDate = false
                });
            }
        }
        catch (Exception ex) { warnings.Add($"Ошибка чтения Prefetch: {ex.Message}"); }
    }

    private static void CollectShimcache(List<EvidenceRecord> evidence, List<string> warnings)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache");
            var bytes = key?.GetValue("AppCompatCache") as byte[];
            if (key is null || bytes is null)
            {
                warnings.Add(@"Shimcache value не найден: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache");
                return;
            }
            var parsed = ForensicArtifactParsers.ParseShimcache(bytes);
            if (!parsed.Supported)
            {
                warnings.Add($"Shimcache: {parsed.Warning}");
                return;
            }
            foreach (var item in parsed.Entries.Where(x =>
                         ArtifactStringExtractor.LooksInteresting(x.Path)
                         || CleanerToolCatalog.LooksLikeTrackedUtility(x.Path)).Take(10_000))
            {
                evidence.Add(new EvidenceRecord
                {
                    TimestampUtc = item.LastModifiedUtc ?? RegistryKeyTimestamps.GetLastWriteUtc(key) ?? DateTimeOffset.UtcNow,
                    RegistryLastWriteUtc = RegistryKeyTimestamps.GetLastWriteUtc(key),
                    Source = "Shimcache/AppCompatCache Parsed",
                    Provider = parsed.Layout,
                    Channel = "Presence",
                    EventId = "PATH_PRESENT",
                    EvidenceCategory = "Program presence",
                    EvidenceStrength = "Indirect",
                    Confidence = "Medium",
                    DeviceHint = item.Path,
                    Summary = $"Shimcache path: {item.Path}",
                    UserExplanation = "Supported AppCompatCache structure parsed. On Windows 10/11 a path entry alone does not prove execution.",
                    Provenance = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache",
                    RawText = $"Layout={parsed.Layout}; LastModifiedUtc={item.LastModifiedUtc:O}; ExecutionProven=false",
                    CanEstablishConnectionDate = false
                });
            }
        }
        catch (Exception ex) { warnings.Add($"Ошибка чтения Shimcache: {ex.Message}"); }
    }

    private static void CollectAmcache(List<EvidenceRecord> evidence, List<string> warnings)
    {
        var source = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "AppCompat", "Programs", "Amcache.hve");
        if (!File.Exists(source))
        {
            warnings.Add($"Amcache.hve не найден: {source}");
            return;
        }
        var temp = Path.Combine(Path.GetTempPath(), "UsbForensicAudit", Guid.NewGuid().ToString("N"));
        var mount = $"UFA_AMCACHE_{Guid.NewGuid():N}";
        var loaded = false;
        try
        {
            Directory.CreateDirectory(temp);
            var copy = Path.Combine(temp, "Amcache.hve");
            File.Copy(source, copy);
            foreach (var suffix in new[] { ".LOG1", ".LOG2" })
                if (File.Exists(source + suffix)) File.Copy(source + suffix, copy + suffix);
            var load = RunReg("load", $@"HKLM\{mount}", copy);
            if (load.ExitCode != 0)
            {
                warnings.Add($"Amcache disposable copy load failed: {load.Output}");
                return;
            }
            loaded = true;
            foreach (var area in new[] { @"Root\InventoryApplicationFile", @"Root\InventoryApplication" })
            {
                using var root = Registry.LocalMachine.OpenSubKey($@"{mount}\{area}");
                if (root is null) continue;
                const int maxAmcacheRecords = 100_000;
                var names = root.GetSubKeyNames();
                if (names.Length > maxAmcacheRecords)
                {
                    warnings.Add($"Amcache {area}: достигнут лимит {maxAmcacheRecords} записей.");
                }
                foreach (var name in names.Take(maxAmcacheRecords))
                {
                    using var item = root.OpenSubKey(name);
                    if (item is null) continue;
                    var path = First(item, "LowerCaseLongPath", "LongPath", "RootDirPath", "Name");
                    if (!ArtifactStringExtractor.LooksInteresting(path) && !CleanerToolCatalog.LooksLikeTrackedUtility(path)) continue;
                    var lastWrite = RegistryKeyTimestamps.GetLastWriteUtc(item);
                    evidence.Add(new EvidenceRecord
                    {
                        TimestampUtc = lastWrite ?? File.GetLastWriteTimeUtc(source),
                        RegistryLastWriteUtc = lastWrite,
                        Source = "Amcache Inventory Parsed",
                        Provider = "Amcache.hve",
                        Channel = area,
                        SourceFile = source,
                        SourceSha256 = HistoricalForensicHelpers.ComputeSha256(source),
                        SourceRecord = $@"{area}\{name}",
                        EventId = "INVENTORY_PRESENCE",
                        EvidenceCategory = "Program/file presence",
                        EvidenceStrength = "Indirect",
                        Confidence = "High",
                        DeviceHint = path,
                        Summary = $"Amcache inventory: {path}",
                        UserExplanation = "Amcache inventory confirms recorded file/application presence; it does not by itself prove execution.",
                        Provenance = $"Source={source}; disposable copy={copy}; key={area}\\{name}",
                        RawText = $"Name={First(item, "Name")}; Publisher={First(item, "Publisher")}; ProgramId={First(item, "ProgramId")}",
                        CanEstablishConnectionDate = false
                    });
                }
            }
        }
        catch (Exception ex) { warnings.Add($"Amcache structural collection: {ex.Message}"); }
        finally
        {
            if (loaded)
            {
                Registry.LocalMachine.Flush();
                var unload = RunReg("unload", $@"HKLM\{mount}");
                if (unload.ExitCode != 0) warnings.Add($"Amcache hive unload: {unload.Output}");
            }
            try { if (Directory.Exists(temp)) Directory.Delete(temp, true); } catch { }
        }
    }

    private static void CollectPca(List<EvidenceRecord> evidence, List<string> warnings)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "AppCompat", "PCA");
        foreach (var fileName in new[] { "PcaAppLaunchDic.txt", "PcaGeneralDb0.txt", "PcaGeneralDb1.txt" })
        {
            var path = Path.Combine(root, fileName);
            if (!File.Exists(path)) continue;
            try
            {
                foreach (var line in File.ReadLines(path).Take(100_000))
                {
                    if (!ArtifactStringExtractor.LooksInteresting(line) && !CleanerToolCatalog.LooksLikeTrackedUtility(line)) continue;
                    var fields = line.Split('|');
                    var timestamp = fields.Select(TryDate).FirstOrDefault(x => x.HasValue);
                    var strength = ClassifyPcaEvidenceStrength(fileName);
                    var isLaunchDictionary = strength == "Corroborating";
                    evidence.Add(new EvidenceRecord
                    {
                        TimestampUtc = timestamp ?? File.GetLastWriteTimeUtc(path),
                        Source = "Windows 11 PCA Parsed",
                        Provider = "Program Compatibility Assistant",
                        Channel = fileName,
                        SourceFile = path,
                        EventId = "PCA_APPLICATION_RECORD",
                        EvidenceCategory = isLaunchDictionary ? "Execution corroboration" : "Compatibility record presence",
                        EvidenceStrength = strength,
                        Confidence = timestamp.HasValue ? "Medium" : "Low",
                        DeviceHint = fields.OrderByDescending(x => x.Length).FirstOrDefault() ?? line,
                        Summary = $"PCA record from {fileName}",
                        UserExplanation = isLaunchDictionary
                            ? "PCA AppLaunchDic corroborates application launch; removable paths are not USB connection dates."
                            : "PCA general database records compatibility processing/presence and is not treated as proof of execution or USB connection.",
                        Provenance = $"Read-only PCA log: {path}",
                        RawText = TextSanitizer.NormalizeDisplay(line, 2000),
                        CanEstablishConnectionDate = false
                    });
                }
            }
            catch (Exception ex) { warnings.Add($"PCA {path}: {ex.Message}"); }
        }
    }

    private static void CollectBamDam(List<EvidenceRecord> evidence, List<string> warnings)
    {
        foreach (var service in new[] { "bam", "dam" })
        {
            var path = $@"SYSTEM\CurrentControlSet\Services\{service}\State\UserSettings";
            try
            {
                using var root = Registry.LocalMachine.OpenSubKey(path);
                if (root is null) continue;
                foreach (var sid in root.GetSubKeyNames().Take(1024))
                {
                    using var user = root.OpenSubKey(sid);
                    if (user is null) continue;
                    foreach (var executable in user.GetValueNames().Take(50_000))
                    {
                        if (!ArtifactStringExtractor.LooksInteresting(executable)
                            && !CleanerToolCatalog.LooksLikeTrackedUtility(executable)) continue;
                        var timestamp = TryFileTime(user.GetValue(executable) as byte[]);
                        evidence.Add(new EvidenceRecord
                        {
                            TimestampUtc = timestamp ?? RegistryKeyTimestamps.GetLastWriteUtc(user) ?? DateTimeOffset.UtcNow,
                            RegistryLastWriteUtc = RegistryKeyTimestamps.GetLastWriteUtc(user),
                            Source = $"{service.ToUpperInvariant()} Parsed",
                            Provider = service.Equals("bam", StringComparison.OrdinalIgnoreCase)
                                ? "Background Activity Moderator" : "Desktop Activity Moderator",
                            Channel = "Execution",
                            EventId = service.ToUpperInvariant() + "_EXECUTION",
                            EvidenceCategory = "Execution corroboration",
                            EvidenceStrength = "Corroborating",
                            Confidence = timestamp.HasValue ? "High" : "Medium",
                            UserSid = sid,
                            ResolvedUserName = UserArtifactCollector.ResolveAccountName(sid, sid),
                            DeviceHint = executable,
                            Summary = $"{service.ToUpperInvariant()} executable record: {executable}",
                            UserExplanation = $"{service.ToUpperInvariant()} is an execution/activity artifact, distinct from PCA; it cannot establish USB connection time.",
                            Provenance = $@"HKLM\{path}\{sid}\{executable}",
                            RawText = $"Artifact={service.ToUpperInvariant()}; TimestampUtc={timestamp:O}",
                            CanEstablishConnectionDate = false
                        });
                    }
                }
            }
            catch (Exception ex) { warnings.Add($"{service.ToUpperInvariant()} collection: {ex.Message}"); }
        }
    }

    private static string First(RegistryKey key, params string[] names)
    {
        foreach (var name in names)
            if (key.GetValue(name) is string value && !string.IsNullOrWhiteSpace(value)) return value;
        return "";
    }

    internal static string ClassifyPcaEvidenceStrength(string fileName) =>
        fileName.Equals("PcaAppLaunchDic.txt", StringComparison.OrdinalIgnoreCase)
            ? "Corroborating"
            : "Indirect";

    internal static string ClassifyPrefetchEvidenceStrength(bool cleanerMatched) =>
        cleanerMatched ? "Direct" : "Indirect";

    internal static DateTimeOffset? TryFileTime(byte[]? bytes)
    {
        if (bytes is null || bytes.Length < 8) return null;
        try { return DateTimeOffset.FromFileTime(BitConverter.ToInt64(bytes, 0)).ToUniversalTime(); }
        catch { return null; }
    }

    private static DateTimeOffset? TryDate(string value) =>
        DateTimeOffset.TryParse(value, out var parsed) ? parsed.ToUniversalTime() : null;

    private static (int ExitCode, string Output) RunReg(string action, string key, string? hive = null)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = hive is null ? $"{action} \"{key}\"" : $"{action} \"{key}\" \"{hive}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };
        process.Start();
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15_000))
        {
            try { process.Kill(true); } catch { }
            return (-1, "reg.exe timeout");
        }
        Task.WaitAll(output, error);
        return (process.ExitCode, TextSanitizer.NormalizeDisplay(output.Result + error.Result, 1000));
    }
}
