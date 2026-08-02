using System.IO;

namespace UsbForensicAudit;

/// <summary>
/// Офлайн-сбор файловых артефактов «что открывали с флешки» из профилей чужой
/// системы: LNK-ярлыки каталога Recent и рабочего стола плюс Jump Lists.
/// Дополняет офлайн-анализ по кустам реестра ответом на главный вопрос
/// расследования — какие файлы открывали со съёмного носителя.
///
/// Живой сбор тех же артефактов делает <see cref="UserArtifactCollector"/>;
/// здесь переиспользуются те же парсеры (<see cref="ShellLinkParser"/>,
/// <see cref="ForensicArtifactParsers"/>), но пути строятся от каталога Users
/// исследуемого образа, а не от реестра текущей машины. Исследуемые файлы
/// только читаются.
/// </summary>
internal static class OfflineUserFileArtifactCollector
{
    /// <summary>
    /// Лимит на профиль: злоумышленник не должен иметь возможность заспамить
    /// отчёт десятками тысяч ярлыков, а честный профиль столько не набирает.
    /// </summary>
    private const int MaxFilesPerProfile = 5000;

    private const int MaxJumpListsPerProfile = 2000;

    internal static void Collect(
        string usersDirectory, AuditResult result, List<string> warnings, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(usersDirectory))
        {
            return;
        }

        foreach (var profile in Directory.EnumerateDirectories(usersDirectory).Take(256))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var userName = Path.GetFileName(profile);
            var recent = Path.Combine(profile, "AppData", "Roaming", "Microsoft", "Windows", "Recent");
            CollectLinks(recent, userName, result, warnings);
            CollectLinks(Path.Combine(profile, "Desktop"), userName, result, warnings);
            CollectJumpLists(recent, userName, result, warnings);
        }
    }

    private static void CollectLinks(
        string root, string userName, AuditResult result, List<string> warnings)
    {
        if (!Directory.Exists(root))
        {
            return;
        }

        try
        {
            var paths = Directory.EnumerateFiles(root, "*.lnk", SearchOption.AllDirectories)
                .Take(MaxFilesPerProfile + 1)
                .ToArray();
            if (paths.Length > MaxFilesPerProfile)
            {
                warnings.Add(
                    $"Офлайн LNK {userName}/{root}: достигнут лимит {MaxFilesPerProfile} файлов, часть пропущена.");
            }

            foreach (var path in paths.Take(MaxFilesPerProfile))
            {
                var link = ShellLinkParser.TryParse(path);
                if (link is null)
                {
                    continue;
                }

                var target = link.BestTarget;
                if (!ForensicArtifactParsers.IsUsbOrVolumeMarker(target) &&
                    !ArtifactStringExtractor.LooksInteresting(target))
                {
                    continue;
                }

                result.Evidence.Add(NewRecord(
                    "Offline User LNK",
                    userName,
                    path,
                    target,
                    link.WriteTimeUtc ?? SafeLastWriteUtc(path),
                    $"VolumeSerial={link.VolumeSerialNumber}; VolumeLabel={link.VolumeLabel}; Target={target}"));
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Офлайн LNK {userName}/{root}: {ex.Message}");
        }
    }

    private static void CollectJumpLists(
        string recent, string userName, AuditResult result, List<string> warnings)
    {
        foreach (var (directory, automatic) in new[]
                 {
                     (Path.Combine(recent, "AutomaticDestinations"), true),
                     (Path.Combine(recent, "CustomDestinations"), false)
                 })
        {
            if (!Directory.Exists(directory))
            {
                continue;
            }

            try
            {
                var paths = Directory.EnumerateFiles(directory).Take(MaxJumpListsPerProfile + 1).ToArray();
                if (paths.Length > MaxJumpListsPerProfile)
                {
                    warnings.Add(
                        $"Офлайн Jump Lists {userName}/{directory}: достигнут лимит {MaxJumpListsPerProfile} файлов.");
                }

                foreach (var path in paths.Take(MaxJumpListsPerProfile))
                {
                    var appId = Path.GetFileName(path).Split('.').FirstOrDefault() ?? "";
                    var bytes = File.ReadAllBytes(path);
                    var entries = automatic
                        ? ForensicArtifactParsers.ParseAutomaticJumpList(bytes, appId)
                        : ForensicArtifactParsers.ParseCustomJumpList(bytes, appId);
                    foreach (var entry in entries)
                    {
                        var target = entry.Link.BestTarget;
                        if (!ForensicArtifactParsers.IsUsbOrVolumeMarker(target) &&
                            !ArtifactStringExtractor.LooksInteresting(target))
                        {
                            continue;
                        }

                        result.Evidence.Add(NewRecord(
                            "Offline Jump List",
                            userName,
                            path,
                            target,
                            entry.EntryTimestampUtc ?? entry.Link.WriteTimeUtc ?? SafeLastWriteUtc(path),
                            $"AppId={entry.AppId}; Stream={entry.StreamName}; " +
                            $"VolumeSerial={entry.Link.VolumeSerialNumber}; Target={target}"));
                    }
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Офлайн Jump Lists {userName}/{directory}: {ex.Message}");
            }
        }
    }

    private static EvidenceRecord NewRecord(
        string source, string userName, string sourceFile, string target,
        DateTimeOffset timestampUtc, string rawText)
    {
        return new EvidenceRecord
        {
            Source = source,
            EvidenceCategory = "Файлы со съёмных носителей",
            Summary = $"Пользователь {userName} открывал «{target}»",
            RawText = TextSanitizer.NormalizeDisplay(rawText, 1000),
            DeviceHint = target,
            TimestampUtc = timestampUtc,
            SourceFile = sourceFile,
            Provenance = $"Offline {sourceFile}",
            // Ярлык доказывает обращение к файлу, но время в LNK описывает
            // метаданные цели, а не момент подключения носителя.
            EvidenceStrength = "Indirect",
            Confidence = "High",
            ResolvedUserName = userName
        };
    }

    private static DateTimeOffset SafeLastWriteUtc(string path)
    {
        try
        {
            return File.GetLastWriteTimeUtc(path);
        }
        catch (Exception)
        {
            return DateTimeOffset.UtcNow;
        }
    }
}
