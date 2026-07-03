using Microsoft.Win32;
using System.IO;

namespace UsbForensicAudit;

public sealed class ExecutionArtifactCollector : IEvidenceCollector
{
    public string ProgressMessage => "Сбор артефактов запуска: Prefetch, Amcache, Shimcache...";

    public bool ShouldRun => true;

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings)
    {
        var evidence = new List<EvidenceRecord>();
        CollectPrefetch(evidence, warnings);
        CollectAmcache(evidence, warnings);
        CollectShimcache(evidence, warnings);
        return evidence;
    }

    private static void CollectPrefetch(List<EvidenceRecord> evidence, List<string> warnings)
    {
        var prefetch = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(prefetch))
        {
            warnings.Add($"Prefetch недоступен или отключен: {prefetch}");
            return;
        }

        try
        {
            foreach (var file in Directory.EnumerateFiles(prefetch, "*.pf").Take(5000))
            {
                var fileName = Path.GetFileName(file);
                var info = new FileInfo(file);
                var cleanerHit = CleanerToolCatalog.Match(fileName);
                var hints = ArtifactStringExtractor.ExtractInterestingStrings(file, maxBytes: 800_000, maxResults: 20);

                if (cleanerHit is null && hints.Count == 0)
                {
                    continue;
                }

                evidence.Add(new EvidenceRecord
                {
                    TimestampUtc = info.LastWriteTimeUtc,
                    Source = "Prefetch",
                    EventId = cleanerHit is null ? "USB_HINT" : "CLEANER_HINT",
                    DeviceHint = hints.Count > 0 ? string.Join("; ", hints) : cleanerHit ?? "",
                    Summary = cleanerHit is null
                        ? $"Prefetch содержит USB/Volume/drive индикаторы: {fileName}"
                        : $"Prefetch: {CleanerToolCatalog.DisplayName(cleanerHit)} ({fileName})",
                    RawText = $"Path={file}{Environment.NewLine}Hints={string.Join(Environment.NewLine, hints)}"
                });
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения Prefetch: {ex.Message}");
        }
    }

    private static void CollectAmcache(List<EvidenceRecord> evidence, List<string> warnings)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "AppCompat", "Programs", "Amcache.hve");
        if (!File.Exists(path))
        {
            warnings.Add($"Amcache.hve не найден: {path}");
            return;
        }

        try
        {
            var info = new FileInfo(path);
            evidence.Add(new EvidenceRecord
            {
                TimestampUtc = info.LastWriteTimeUtc,
                Source = "Amcache",
                EventId = "HIVE_PRESENT",
                Summary = $"Найден Amcache.hve: {path}",
                RawText = $"Created={info.CreationTimeUtc:O}; Modified={info.LastWriteTimeUtc:O}; Size={info.Length:N0}"
            });

            var hints = ArtifactStringExtractor.ExtractInterestingStrings(path, maxBytes: 8_000_000, maxResults: 60);
            foreach (var hint in hints)
            {
                evidence.Add(new EvidenceRecord
                {
                    TimestampUtc = info.LastWriteTimeUtc,
                    Source = "Amcache String Scan",
                    EventId = CleanerToolCatalog.LooksLikeCleaner(hint) ? "CLEANER_HINT" : "USB_HINT",
                    DeviceHint = hint,
                    Summary = "Amcache.hve содержит USB/Volume/drive или cleaner индикатор",
                    RawText = hint
                });
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения Amcache.hve: {ex.Message}");
        }
    }

    private static void CollectShimcache(List<EvidenceRecord> evidence, List<string> warnings)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache");
            if (key is null)
            {
                warnings.Add(@"Shimcache key не найден: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache");
                return;
            }

            var value = key.GetValue("AppCompatCache");
            var length = value is byte[] bytes ? bytes.Length : 0;
            evidence.Add(new EvidenceRecord
            {
                Source = "Shimcache/AppCompatCache",
                EventId = "VALUE_PRESENT",
                Summary = "Найден AppCompatCache. Полный структурный парсер будет добавлен отдельным модулем.",
                RawText = $"ValueLength={length:N0}; ValueKind={key.GetValueKind("AppCompatCache")}"
            });
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка чтения Shimcache/AppCompatCache: {ex.Message}");
        }
    }
}
