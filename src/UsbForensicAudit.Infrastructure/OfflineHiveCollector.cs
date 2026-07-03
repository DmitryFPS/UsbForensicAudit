using System.Diagnostics;
using System.IO;
using System.Text;
using Microsoft.Win32;

namespace UsbForensicAudit;

public sealed class OfflineHiveCollector : IEvidenceCollector
{
    public string ProgressMessage => "Offline-анализ NTUSER.DAT и UsrClass.dat...";

    public bool ShouldRun => true;

    private static readonly string[] NtUserPaths =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
    ];

    private static readonly string[] UsrClassPaths =
    [
        @"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
        @"Local Settings\Software\Microsoft\Windows\Shell\Bags"
    ];

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings)
    {
        var evidence = new List<EvidenceRecord>();
        var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? @"C:\";
        var usersRoot = Path.Combine(systemDrive, "Users");
        if (!Directory.Exists(usersRoot))
        {
            warnings.Add($"Offline hive: папка профилей не найдена: {usersRoot}");
            return evidence;
        }

        foreach (var profile in Directory.EnumerateDirectories(usersRoot))
        {
            var userName = Path.GetFileName(profile);
            if (IsSystemProfile(userName))
            {
                continue;
            }

            LoadAndCollect(Path.Combine(profile, "NTUSER.DAT"), userName, "NTUSER.DAT", NtUserPaths, evidence, warnings);
            LoadAndCollect(Path.Combine(profile, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"), userName, "UsrClass.dat", UsrClassPaths, evidence, warnings);
        }

        return evidence;
    }

    private static void LoadAndCollect(string hivePath, string userName, string hiveName, IReadOnlyList<string> relativePaths, List<EvidenceRecord> evidence, List<string> warnings)
    {
        if (!File.Exists(hivePath))
        {
            return;
        }

        var mountName = $"UFA_{Guid.NewGuid():N}";
        var loaded = false;
        try
        {
            var load = RunReg("load", $@"HKU\{mountName}", hivePath);
            if (load.ExitCode != 0)
            {
                warnings.Add($"Offline hive: не удалось загрузить {hivePath}: {TextSanitizer.NormalizeDisplay(load.Output, 500)}");
                return;
            }

            loaded = true;
            using var root = Registry.Users.OpenSubKey(mountName);
            if (root is null)
            {
                warnings.Add($"Offline hive: hive загружен, но HKU\\{mountName} не открылся");
                return;
            }

            foreach (var relativePath in relativePaths)
            {
                using var key = root.OpenSubKey(relativePath);
                if (key is null)
                {
                    continue;
                }

                CollectRecursive(key, $@"HKU\{mountName}\{relativePath}", userName, hiveName, relativePath, evidence, maxDepth: 8, maxItems: 800);
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Offline hive: ошибка обработки {hivePath}: {ex.Message}");
        }
        finally
        {
            if (loaded)
            {
                Registry.Users.Flush();
                var unload = RunReg("unload", $@"HKU\{mountName}");
                if (unload.ExitCode != 0)
                {
                    warnings.Add($"Offline hive: не удалось выгрузить HKU\\{mountName}: {unload.Output}");
                }
            }
        }
    }

    private static int CollectRecursive(RegistryKey key, string displayPath, string userName, string hiveName, string rootArtifact, List<EvidenceRecord> evidence, int maxDepth, int maxItems)
    {
        if (maxDepth < 0 || maxItems <= 0)
        {
            return 0;
        }

        var added = 0;
        if (ArtifactStringExtractor.LooksInteresting(displayPath) || displayPath.Contains("Volume", StringComparison.OrdinalIgnoreCase) || rootArtifact.Contains("BagMRU", StringComparison.OrdinalIgnoreCase))
        {
            evidence.Add(new EvidenceRecord
            {
                Source = $"Offline Hive {hiveName}",
                EventId = userName,
                DeviceHint = Shorten(displayPath, 220),
                Summary = $"{rootArtifact}: {displayPath}",
                RawText = displayPath
            });
            added++;
        }

        foreach (var valueName in key.GetValueNames())
        {
            if (added >= maxItems)
            {
                return added;
            }

            var valueText = ValueToSearchText(key.GetValue(valueName));
            if (ArtifactStringExtractor.LooksInteresting(valueName) || ArtifactStringExtractor.LooksInteresting(valueText))
            {
                evidence.Add(new EvidenceRecord
                {
                    Source = $"Offline Hive {hiveName}",
                    EventId = userName,
                    DeviceHint = Shorten(valueName, 160),
                    Summary = $"{rootArtifact}: {displayPath}\\{valueName}",
                    RawText = Shorten(valueText, 1000)
                });
                added++;
            }
        }

        foreach (var subName in key.GetSubKeyNames())
        {
            if (added >= maxItems)
            {
                break;
            }

            try
            {
                using var subKey = key.OpenSubKey(subName);
                if (subKey is null)
                {
                    continue;
                }

                added += CollectRecursive(subKey, $@"{displayPath}\{subName}", userName, hiveName, rootArtifact, evidence, maxDepth - 1, maxItems - added);
            }
            catch
            {
                // Некоторые узлы shellbag могут быть недоступны для чтения на работающей системе.
            }
        }

        return added;
    }

    private static (int ExitCode, string Output) RunReg(string action, string keyPath, string? hivePath = null)
    {
        var args = hivePath is null
            ? $"{action} \"{keyPath}\""
            : $"{action} \"{keyPath}\" \"{hivePath}\"";

        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = "reg.exe",
            Arguments = args,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        };

        process.Start();
        using var outputStream = new MemoryStream();
        process.StandardOutput.BaseStream.CopyTo(outputStream);
        process.StandardError.BaseStream.CopyTo(outputStream);
        var output = TextSanitizer.NormalizeConsoleOutput(outputStream.ToArray());
        if (!process.WaitForExit(15_000))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Очистка по возможности; вызывающий код фиксирует таймаут.
            }

            return (-1, "reg.exe timeout");
        }

        return (process.ExitCode, output.Trim());
    }

    private static string ValueToSearchText(object? value)
    {
        return value switch
        {
            byte[] bytes => Encoding.Unicode.GetString(bytes) + "\n" + Encoding.UTF8.GetString(bytes),
            string text => text,
            string[] values => string.Join("; ", values),
            _ => value?.ToString() ?? ""
        };
    }

    private static string Shorten(string value, int max)
    {
        return value.Length <= max ? value : value[..max];
    }

    private static bool IsSystemProfile(string userName)
    {
        return userName.Equals("All Users", StringComparison.OrdinalIgnoreCase)
               || userName.Equals("Default", StringComparison.OrdinalIgnoreCase)
               || userName.Equals("Default User", StringComparison.OrdinalIgnoreCase)
               || userName.Equals("Public", StringComparison.OrdinalIgnoreCase);
    }
}
