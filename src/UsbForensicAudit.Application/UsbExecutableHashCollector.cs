using System.Text.RegularExpressions;

namespace UsbForensicAudit;

/// <summary>
/// Находит в артефактах запуска (Prefetch/Amcache) пути исполняемых файлов,
/// запускавшихся со съёмных носителей, и считает их хеши через порт IFileHasher.
/// Извлечение путей чистое и тестируемое; чтение файла — за портом. Сеть не
/// используется: сверка с образцами остаётся на стороне пользователя.
/// </summary>
public static partial class UsbExecutableHashCollector
{
    // Путь вида X:\...\name.exe. Буква тома внешнего носителя определяется отдельно
    // по буквам, отнесённым к внешним устройствам в этом же аудите.
    [GeneratedRegex(@"(?<drive>[A-Za-z]):\\[^""|<>\r\n]*?\.exe", RegexOptions.IgnoreCase)]
    private static partial Regex ExePathRegex();

    /// <summary>
    /// Извлекает уникальные пути к .exe со съёмных носителей из доказательств
    /// запуска. Носителем считается том, чья буква отнесена к внешнему устройству.
    /// </summary>
    public static IReadOnlyList<string> ExtractRemovableExePaths(AuditResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var removableDrives = result.Devices
            .Where(d => d.IsExternalDevice)
            .SelectMany(d => (d.DriveLetters ?? string.Empty)
                .Where(char.IsLetter)
                .Select(char.ToUpperInvariant))
            .ToHashSet();

        if (removableDrives.Count == 0)
        {
            return [];
        }

        var paths = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var evidence in result.Evidence)
        {
            if (!IsExecutionSource(evidence.Source))
            {
                continue;
            }

            foreach (var haystack in new[] { evidence.RawText, evidence.DeviceHint, evidence.Summary })
            {
                if (string.IsNullOrEmpty(haystack))
                {
                    continue;
                }

                foreach (Match match in ExePathRegex().Matches(haystack))
                {
                    var drive = char.ToUpperInvariant(match.Groups["drive"].Value[0]);
                    if (removableDrives.Contains(drive) && seen.Add(match.Value))
                    {
                        paths.Add(match.Value);
                    }
                }
            }
        }

        return paths;
    }

    /// <summary>Считает хеши найденных путей через переданный хешер.</summary>
    public static IReadOnlyList<FileHashRecord> Collect(IEnumerable<string> paths, IFileHasher hasher)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(hasher);

        return paths.Select(hasher.Hash).ToArray();
    }

    private static bool IsExecutionSource(string? source) =>
        !string.IsNullOrEmpty(source)
        && (source.Contains("Prefetch", StringComparison.OrdinalIgnoreCase)
            || source.Contains("Amcache", StringComparison.OrdinalIgnoreCase));
}
