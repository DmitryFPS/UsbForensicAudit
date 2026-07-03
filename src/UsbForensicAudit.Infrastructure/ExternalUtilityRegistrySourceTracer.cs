using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace UsbForensicAudit;

/// <summary>
/// Ищет VID/PID в типичных ветках реестра, которые читает USBDetector (аналог Procmon без внешней утилиты).
/// </summary>
public static class ExternalUtilityRegistrySourceTracer
{
    private static readonly Regex VidPidRegex = new(@"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static IReadOnlyList<ExternalUtilitySourceHit> Trace(string? vid, string? pid, int maxHitsPerSource = 3)
    {
        if (string.IsNullOrWhiteSpace(vid))
        {
            return [];
        }

        vid = vid.ToUpperInvariant();
        pid = string.IsNullOrWhiteSpace(pid) ? null : pid.ToUpperInvariant();
        var hits = new List<ExternalUtilitySourceHit>();

        ScanEnumUsb(vid, pid, hits, maxHitsPerSource);
        ScanEnumUsbStor(vid, pid, hits, maxHitsPerSource);
        ScanMountedDevices(vid, pid, hits, maxHitsPerSource);
        ScanWpdDevices(vid, pid, hits, maxHitsPerSource);
        ScanMountPoints2(vid, pid, hits, maxHitsPerSource);

        AppendMissingChecks(vid, pid, hits);
        return hits;
    }

    private static void AppendMissingChecks(string vid, string? pid, List<ExternalUtilitySourceHit> hits)
    {
        AddIfMissing(hits, "Enum\\USB", @"HKLM\SYSTEM\CurrentControlSet\Enum\USB", Likely: true);
        AddIfMissing(hits, "Enum\\USBSTOR", @"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR", Likely: true);
        AddIfMissing(hits, "MountedDevices", @"HKLM\SYSTEM\MountedDevices", Likely: true);
        AddIfMissing(hits, "WPD Devices", @"HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices", Likely: false);
        AddIfMissing(hits, "MountPoints2", @"HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2", Likely: true);

        static void AddIfMissing(List<ExternalUtilitySourceHit> list, string title, string path, bool Likely)
        {
            if (list.Any(x => x.Title.Equals(title, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            list.Add(new ExternalUtilitySourceHit
            {
                Title = title,
                RegistryPath = path,
                Found = false,
                ResultText = "запись с этим VID/PID не найдена",
                LikelyUsbDetectorSource = Likely
            });
        }
    }

    private static void ScanEnumUsb(string vid, string? pid, List<ExternalUtilitySourceHit> hits, int maxHits)
    {
        const string rootPath = @"SYSTEM\CurrentControlSet\Enum\USB";
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(rootPath);
            if (root is null)
            {
                hits.Add(Miss("Enum\\USB", @"HKLM\" + rootPath, "ветка недоступна"));
                return;
            }

            var matches = new List<string>();
            foreach (var familyName in root.GetSubKeyNames())
            {
                if (!MatchesVidPid(familyName, vid, pid))
                {
                    continue;
                }

                foreach (var instance in root.OpenSubKey(familyName)?.GetSubKeyNames().Take(maxHits) ?? [])
                {
                    matches.Add($@"HKLM\{rootPath}\{familyName}\{instance}");
                    if (matches.Count >= maxHits)
                    {
                        break;
                    }
                }

                if (matches.Count >= maxHits)
                {
                    break;
                }
            }

            if (matches.Count == 0)
            {
                hits.Add(Miss("Enum\\USB", @"HKLM\" + rootPath, "нет ключа VID_…&PID_…"));
                return;
            }

            hits.Add(new ExternalUtilitySourceHit
            {
                Title = "Enum\\USB",
                RegistryPath = matches[0],
                Found = true,
                ResultText = matches.Count == 1
                    ? "найден ключ установки USB"
                    : $"найдено ключей: {matches.Count}",
                LikelyUsbDetectorSource = true
            });
        }
        catch (Exception ex)
        {
            hits.Add(Miss("Enum\\USB", @"HKLM\" + rootPath, $"ошибка чтения: {ex.Message}"));
        }
    }

    private static void ScanEnumUsbStor(string vid, string? pid, List<ExternalUtilitySourceHit> hits, int maxHits)
    {
        const string rootPath = @"SYSTEM\CurrentControlSet\Enum\USBSTOR";
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(rootPath);
            if (root is null)
            {
                hits.Add(Miss("Enum\\USBSTOR", @"HKLM\" + rootPath, "ветка недоступна"));
                return;
            }

            var matches = new List<string>();
            foreach (var familyName in root.GetSubKeyNames())
            {
                var familyVidPid = VidPidRegex.Match(familyName);
                if (familyVidPid.Success && MatchesPair(familyVidPid.Groups[1].Value, familyVidPid.Groups[2].Value, vid, pid))
                {
                    matches.Add($@"HKLM\{rootPath}\{familyName}");
                }
                else if (pid is null && familyName.Contains($"VID_{vid}", StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add($@"HKLM\{rootPath}\{familyName}");
                }

                if (matches.Count >= maxHits)
                {
                    break;
                }
            }

            if (matches.Count == 0)
            {
                hits.Add(Miss("Enum\\USBSTOR", @"HKLM\" + rootPath, "нет записи накопителя с этим VID/PID"));
                return;
            }

            hits.Add(new ExternalUtilitySourceHit
            {
                Title = "Enum\\USBSTOR",
                RegistryPath = matches[0],
                Found = true,
                ResultText = "найден след USB Mass Storage",
                LikelyUsbDetectorSource = true
            });
        }
        catch (Exception ex)
        {
            hits.Add(Miss("Enum\\USBSTOR", @"HKLM\" + rootPath, $"ошибка чтения: {ex.Message}"));
        }
    }

    private static void ScanMountedDevices(string vid, string? pid, List<ExternalUtilitySourceHit> hits, int maxHits)
    {
        const string rootPath = @"SYSTEM\MountedDevices";
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(rootPath);
            if (root is null)
            {
                hits.Add(Miss("MountedDevices", @"HKLM\" + rootPath, "ветка недоступна"));
                return;
            }

            var needle = pid is null
                ? $"VID_{vid}"
                : $"VID_{vid}&PID_{pid}";
            var matches = new List<string>();

            foreach (var valueName in root.GetValueNames())
            {
                if (valueName.Contains(needle, StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add($@"HKLM\{rootPath} → {valueName}");
                    continue;
                }

                var value = root.GetValue(valueName);
                if (value is byte[] bytes && ContainsAscii(bytes, needle))
                {
                    matches.Add($@"HKLM\{rootPath} → {valueName} (бинарное значение)");
                }

                if (matches.Count >= maxHits)
                {
                    break;
                }
            }

            if (matches.Count == 0)
            {
                hits.Add(Miss("MountedDevices", @"HKLM\" + rootPath, "нет следов монтирования с этим VID/PID"));
                return;
            }

            hits.Add(new ExternalUtilitySourceHit
            {
                Title = "MountedDevices",
                RegistryPath = matches[0],
                Found = true,
                ResultText = "найден след тома/буквы диска",
                LikelyUsbDetectorSource = true
            });
        }
        catch (Exception ex)
        {
            hits.Add(Miss("MountedDevices", @"HKLM\" + rootPath, $"ошибка чтения: {ex.Message}"));
        }
    }

    private static void ScanWpdDevices(string vid, string? pid, List<ExternalUtilitySourceHit> hits, int maxHits)
    {
        const string rootPath = @"SOFTWARE\Microsoft\Windows Portable Devices\Devices";
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(rootPath);
            if (root is null)
            {
                hits.Add(Miss("WPD Devices", @"HKLM\" + rootPath, "ветка отсутствует или пуста"));
                return;
            }

            var matches = new List<string>();
            foreach (var subName in root.GetSubKeyNames())
            {
                if (!MatchesVidPid(subName, vid, pid))
                {
                    continue;
                }

                matches.Add($@"HKLM\{rootPath}\{subName}");
                if (matches.Count >= maxHits)
                {
                    break;
                }
            }

            if (matches.Count == 0)
            {
                hits.Add(Miss("WPD Devices", @"HKLM\" + rootPath, "нет portable/MTP устройства с этим VID/PID"));
                return;
            }

            hits.Add(new ExternalUtilitySourceHit
            {
                Title = "WPD Devices",
                RegistryPath = matches[0],
                Found = true,
                ResultText = "найден portable/MTP след",
                LikelyUsbDetectorSource = false
            });
        }
        catch (Exception ex)
        {
            hits.Add(Miss("WPD Devices", @"HKLM\" + rootPath, $"ошибка чтения: {ex.Message}"));
        }
    }

    private static void ScanMountPoints2(string vid, string? pid, List<ExternalUtilitySourceHit> hits, int maxHits)
    {
        const string relative = @"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2";
        try
        {
            using var users = Registry.Users;
            var matches = new List<string>();
            foreach (var sid in users.GetSubKeyNames().Where(x => x.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase) && !x.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)))
            {
                using var key = users.OpenSubKey($@"{sid}\{relative}");
                if (key is null)
                {
                    continue;
                }

                foreach (var subName in key.GetSubKeyNames())
                {
                    if (!ContainsVidPidText(subName, vid, pid))
                    {
                        continue;
                    }

                    matches.Add($@"HKU\{sid}\{relative}\{subName}");
                    if (matches.Count >= maxHits)
                    {
                        break;
                    }
                }

                if (matches.Count >= maxHits)
                {
                    break;
                }
            }

            if (matches.Count == 0)
            {
                hits.Add(new ExternalUtilitySourceHit
                {
                    Title = "MountPoints2",
                    RegistryPath = @"HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
                    Found = false,
                    ResultText = "нет подключённых точек монтирования с этим VID/PID",
                    LikelyUsbDetectorSource = true
                });
                return;
            }

            hits.Add(new ExternalUtilitySourceHit
            {
                Title = "MountPoints2",
                RegistryPath = matches[0],
                Found = true,
                ResultText = "найден след Explorer MountPoints2",
                LikelyUsbDetectorSource = true
            });
        }
        catch (Exception ex)
        {
            hits.Add(Miss("MountPoints2", @"HKU\<SID>\…\MountPoints2", $"ошибка чтения: {ex.Message}"));
        }
    }

    private static bool MatchesVidPid(string text, string vid, string? pid)
    {
        var match = VidPidRegex.Match(text);
        if (match.Success)
        {
            return MatchesPair(match.Groups[1].Value, match.Groups[2].Value, vid, pid);
        }

        return pid is null && text.Contains($"VID_{vid}", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsVidPidText(string text, string vid, string? pid) =>
        pid is null
            ? text.Contains($"VID_{vid}", StringComparison.OrdinalIgnoreCase) || text.Contains(vid, StringComparison.OrdinalIgnoreCase)
            : text.Contains($"VID_{vid}&PID_{pid}", StringComparison.OrdinalIgnoreCase)
              || text.Contains($"VID_{vid}", StringComparison.OrdinalIgnoreCase);

    private static bool MatchesPair(string foundVid, string foundPid, string vid, string? pid) =>
        foundVid.Equals(vid, StringComparison.OrdinalIgnoreCase)
        && (pid is null || foundPid.Equals(pid, StringComparison.OrdinalIgnoreCase));

    private static bool ContainsAscii(byte[] bytes, string needle)
    {
        var text = Encoding.ASCII.GetString(bytes);
        return text.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private static ExternalUtilitySourceHit Miss(string title, string path, string result) => new()
    {
        Title = title,
        RegistryPath = path,
        Found = false,
        ResultText = result,
        LikelyUsbDetectorSource = title is "Enum\\USB" or "Enum\\USBSTOR" or "MountedDevices" or "MountPoints2"
    };
}
