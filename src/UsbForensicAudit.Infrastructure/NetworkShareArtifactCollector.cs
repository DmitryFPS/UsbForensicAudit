using System.IO;
using Microsoft.Win32;

namespace UsbForensicAudit;

/// <summary>
/// Куда ходили по сети: какие сетевые папки открывали, какие подключали диском,
/// какие адреса вводили руками, к каким узлам удалённого стола обращались.
///
/// Журналы говорят, что связь с сервером была; следы пользователя говорят, что
/// именно на нём открывали. Разница между «машина соединялась с 20.20.20.76» и
/// «открывали \\20.20.20.76\soft» — это разница между наличием связи и работой
/// с чужими файлами, и в отчёте она должна быть видна.
///
/// Все следы здесь оставлены самим проводником и хранят путь, а не время
/// действия: у ключа реестра есть только время последней записи в ветку, у
/// ярлыка — время его последнего изменения. Поэтому у каждого обращения записано,
/// что означает его отметка времени.
/// </summary>
internal sealed class NetworkShareArtifactCollector : INetworkArtifactCollector
{
    private const string ExplorerPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer";
    private const string TerminalClientPath = @"SOFTWARE\Microsoft\Terminal Server Client";

    private const int MaxValuesPerKey = 500;
    private const int MaxShortcuts = 5000;
    private const int MaxShellBagNodes = 20000;

    public string ProgressMessage => "Поиск сетевых папок и адресов в следах пользователей...";

    public bool ShouldRun => true;

    public NetworkArtifactSet Collect(List<string> warnings)
    {
        var buckets = new Dictionary<string, Bucket>(StringComparer.OrdinalIgnoreCase);
        var profiles = UserArtifactCollector.ResolveProfiles(warnings);

        try
        {
            using var users = Registry.Users;
            foreach (var (sid, profile) in profiles.Where(x => IsUserSid(x.Key)))
            {
                ReadMappedDrives(users, sid, profile, buckets, warnings);
                ReadTextValues(users, sid, profile, buckets, warnings,
                    $@"{ExplorerPath}\Map Network Drive MRU",
                    "Реестр Windows — список подключений сетевого диска",
                    NetworkVisitKind.RememberedShare,
                    "Момент последней записи в ветку списка: относится ко всей ветке, а не к этой строке");
                ReadTextValues(users, sid, profile, buckets, warnings,
                    $@"{ExplorerPath}\TypedPaths",
                    "Реестр Windows — пути, введённые в адресной строке проводника",
                    NetworkVisitKind.TypedPath,
                    "Момент последней записи в ветку введённых путей");
                ReadTextValues(users, sid, profile, buckets, warnings,
                    $@"{ExplorerPath}\RunMRU",
                    "Реестр Windows — окно «Выполнить»",
                    NetworkVisitKind.TypedPath,
                    "Момент последней записи в ветку окна «Выполнить»");
                ReadRememberedShares(users, sid, profile, buckets, warnings);
                ReadRemoteDesktopHosts(users, sid, profile, buckets, warnings);
                ReadShellBags(users, sid, profile, buckets, warnings);
                ReadShortcuts(profile, buckets, warnings);
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Поиск сетевых папок в следах пользователей не выполнен: {exception.Message}");
        }

        return NetworkArtifactSet.FromConnections(Finish(buckets.Values));
    }

    /// <summary>Учётные записи людей; служебные записи Windows пропускаются.</summary>
    private static bool IsUserSid(string sid) =>
        sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
        && !sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Сетевые папки, подключённые как диск. Такое подключение восстанавливается
    /// при каждом входе в систему, поэтому запись означает не единичный заход, а
    /// постоянную работу с этой папкой.
    /// </summary>
    private static void ReadMappedDrives(
        RegistryKey users,
        string sid,
        UserProfileIdentity profile,
        Dictionary<string, Bucket> buckets,
        List<string> warnings)
    {
        try
        {
            using var root = users.OpenSubKey($@"{sid}\Network");
            if (root is null)
            {
                return;
            }

            foreach (var letter in root.GetSubKeyNames())
            {
                using var key = root.OpenSubKey(letter);
                var remote = key?.GetValue("RemotePath") as string ?? "";
                if (!NetworkTarget.IsUncPath(remote))
                {
                    continue;
                }

                var account = key?.GetValue("UserName") as string ?? "";
                AddVisit(buckets, remote, new NetworkVisit
                {
                    WhenUtc = key is null ? null : RegistryKeyTimestamps.GetLastWriteUtc(key),
                    Kind = NetworkVisitKind.MappedDrive,
                    Target = remote,
                    Title = $"Подключена как диск {letter.ToUpperInvariant()}:"
                            + (account.Length > 0 ? $", под учётной записью {account}" : ""),
                    UserSid = sid,
                    ResolvedUserName = profile.ResolvedUserName,
                    Source = "Реестр Windows — сетевые диски пользователя",
                    TimeMeaning = "Момент последней записи в ветку этого диска",
                    Provenance = $@"HKU\{sid}\Network\{letter}"
                }, account);
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Сетевые диски пользователя {profile.ResolvedUserName} не прочитаны: {exception.Message}");
        }
    }

    /// <summary>Значения-строки, среди которых встречаются сетевые пути и адреса.</summary>
    private static void ReadTextValues(
        RegistryKey users,
        string sid,
        UserProfileIdentity profile,
        Dictionary<string, Bucket> buckets,
        List<string> warnings,
        string relative,
        string source,
        string kind,
        string timeMeaning)
    {
        try
        {
            using var key = users.OpenSubKey($@"{sid}\{relative}");
            if (key is null)
            {
                return;
            }

            var written = RegistryKeyTimestamps.GetLastWriteUtc(key);
            foreach (var name in key.GetValueNames().Take(MaxValuesPerKey))
            {
                var value = (key.GetValue(name) as string ?? "").Trim();
                if (value.Length == 0)
                {
                    continue;
                }

                AddVisit(buckets, value, new NetworkVisit
                {
                    WhenUtc = written,
                    Kind = kind,
                    Target = value,
                    UserSid = sid,
                    ResolvedUserName = profile.ResolvedUserName,
                    Source = source,
                    TimeMeaning = timeMeaning,
                    Provenance = $@"HKU\{sid}\{relative}\{name}"
                });
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Ветка {relative} у {profile.ResolvedUserName} не прочитана: {exception.Message}");
        }
    }

    /// <summary>
    /// Сетевые папки, запомненные проводником. Он записывает их под именем вида
    /// «##20.20.20.76#soft», где решётки стоят вместо косых черт.
    /// </summary>
    private static void ReadRememberedShares(
        RegistryKey users,
        string sid,
        UserProfileIdentity profile,
        Dictionary<string, Bucket> buckets,
        List<string> warnings)
    {
        const string relative = $@"{ExplorerPath}\MountPoints2";
        try
        {
            using var root = users.OpenSubKey($@"{sid}\{relative}");
            if (root is null)
            {
                return;
            }

            foreach (var name in root.GetSubKeyNames().Take(MaxValuesPerKey))
            {
                if (!name.StartsWith("##", StringComparison.Ordinal))
                {
                    continue;
                }

                using var key = root.OpenSubKey(name);
                var path = @"\\" + name[2..].Replace('#', '\\');
                AddVisit(buckets, path, new NetworkVisit
                {
                    WhenUtc = key is null ? null : RegistryKeyTimestamps.GetLastWriteUtc(key),
                    Kind = NetworkVisitKind.RememberedShare,
                    Target = path,
                    UserSid = sid,
                    ResolvedUserName = profile.ResolvedUserName,
                    Source = "Реестр Windows — сетевые папки, запомненные проводником",
                    TimeMeaning = "Момент последней записи в ветку этой папки",
                    Provenance = $@"HKU\{sid}\{relative}\{name}"
                });
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Запомненные сетевые папки у {profile.ResolvedUserName} не прочитаны: {exception.Message}");
        }
    }

    /// <summary>
    /// Узлы, к которым подключались по удалённому столу. Клиент запоминает их
    /// вместе с именем учётной записи, под которой входили.
    /// </summary>
    private static void ReadRemoteDesktopHosts(
        RegistryKey users,
        string sid,
        UserProfileIdentity profile,
        Dictionary<string, Bucket> buckets,
        List<string> warnings)
    {
        try
        {
            using var servers = users.OpenSubKey($@"{sid}\{TerminalClientPath}\Servers");
            if (servers is not null)
            {
                foreach (var host in servers.GetSubKeyNames().Take(MaxValuesPerKey))
                {
                    if (!NetworkTarget.LooksLikeHost(host))
                    {
                        continue;
                    }

                    using var key = servers.OpenSubKey(host);
                    var hint = key?.GetValue("UsernameHint") as string ?? "";
                    var bucket = Bucket.For(buckets, NetworkConnectionKind.RemoteDesktop, host, () =>
                        new NetworkConnectionRecord
                        {
                            Kind = NetworkConnectionKind.RemoteDesktop,
                            Name = host,
                            Direction = NetworkDirection.Outgoing,
                            Account = hint,
                            Source = "Реестр Windows — узлы удалённого стола",
                            Details = NetworkConnectionExplanations.RemoteDesktopOutgoing
                                      + ". Клиент запоминает узел при подключении, поэтому запись означает "
                                      + "состоявшуюся попытку соединения",
                            Provenance = $@"HKU\{sid}\{TerminalClientPath}\Servers\{host}"
                        });

                    bucket.Record.Account = FirstNotEmpty(bucket.Record.Account, hint);
                    bucket.AddVisit(new NetworkVisit
                    {
                        WhenUtc = key is null ? null : RegistryKeyTimestamps.GetLastWriteUtc(key),
                        Kind = NetworkVisitKind.Host,
                        Target = host,
                        Title = hint.Length > 0 ? $"Входили под учётной записью {hint}" : "",
                        UserSid = sid,
                        ResolvedUserName = profile.ResolvedUserName,
                        Source = "Реестр Windows — узлы удалённого стола",
                        TimeMeaning = "Момент последней записи в ветку этого узла",
                        Provenance = $@"HKU\{sid}\{TerminalClientPath}\Servers\{host}"
                    });
                }
            }

            using var last = users.OpenSubKey($@"{sid}\{TerminalClientPath}\Default");
            if (last is null)
            {
                return;
            }

            var written = RegistryKeyTimestamps.GetLastWriteUtc(last);
            foreach (var name in last.GetValueNames().Take(MaxValuesPerKey))
            {
                var host = (last.GetValue(name) as string ?? "").Trim();
                if (!NetworkTarget.LooksLikeHost(host))
                {
                    continue;
                }

                var bucket = Bucket.For(buckets, NetworkConnectionKind.RemoteDesktop, host, () =>
                    new NetworkConnectionRecord
                    {
                        Kind = NetworkConnectionKind.RemoteDesktop,
                        Name = host,
                        Direction = NetworkDirection.Outgoing,
                        Source = "Реестр Windows — последние узлы удалённого стола",
                        Provenance = $@"HKU\{sid}\{TerminalClientPath}\Default\{name}"
                    });

                bucket.AddVisit(new NetworkVisit
                {
                    WhenUtc = written,
                    Kind = NetworkVisitKind.Host,
                    Target = host,
                    Title = $"Записан в списке последних подключений под номером {name}",
                    UserSid = sid,
                    ResolvedUserName = profile.ResolvedUserName,
                    Source = "Реестр Windows — последние узлы удалённого стола",
                    TimeMeaning = "Момент последней записи в ветку списка последних подключений",
                    Provenance = $@"HKU\{sid}\{TerminalClientPath}\Default\{name}"
                });
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Узлы удалённого стола у {profile.ResolvedUserName} не прочитаны: {exception.Message}");
        }
    }

    /// <summary>
    /// Папки, которые открывали в проводнике. Проводник запоминает каждую
    /// открытую папку в своём дереве, и сетевые папки попадают туда вместе с
    /// остальными.
    /// </summary>
    private static void ReadShellBags(
        RegistryKey users,
        string sid,
        UserProfileIdentity profile,
        Dictionary<string, Bucket> buckets,
        List<string> warnings)
    {
        foreach (var relative in new[]
                 {
                     $@"{sid}_Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
                     $@"{sid}\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
                     $@"{sid}\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell\BagMRU"
                 })
        {
            try
            {
                using var root = users.OpenSubKey(relative);
                if (root is null)
                {
                    continue;
                }

                var visited = 0;
                WalkShellBags(root, $@"HKU\{relative}", sid, profile, buckets, ref visited, 0);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                warnings.Add($"Дерево открытых папок у {profile.ResolvedUserName} прочитано не полностью: "
                             + exception.Message);
            }
        }
    }

    private static void WalkShellBags(
        RegistryKey key,
        string path,
        string sid,
        UserProfileIdentity profile,
        Dictionary<string, Bucket> buckets,
        ref int visited,
        int depth)
    {
        if (depth > 24 || visited > MaxShellBagNodes)
        {
            return;
        }

        visited++;
        var written = RegistryKeyTimestamps.GetLastWriteUtc(key);

        foreach (var name in key.GetValueNames())
        {
            if (key.GetValue(name) is not byte[] bytes || bytes.Length < 8)
            {
                continue;
            }

            var parsed = ForensicArtifactParsers.ParsePidl(bytes);
            foreach (var candidate in new[] { parsed?.BestPath ?? "" }
                         .Concat(parsed?.PathFragments ?? [])
                         .Where(NetworkTarget.IsUncPath))
            {
                AddVisit(buckets, candidate, new NetworkVisit
                {
                    WhenUtc = written,
                    Kind = NetworkVisitKind.Folder,
                    Target = candidate,
                    UserSid = sid,
                    ResolvedUserName = profile.ResolvedUserName,
                    Source = "Реестр Windows — папки, открытые в проводнике",
                    TimeMeaning = "Момент последней записи в эту ветку дерева папок; относится ко всей "
                                  + "ветке, а не к одному открытию",
                    Provenance = $@"{path}\{name}"
                });
            }
        }

        foreach (var child in key.GetSubKeyNames())
        {
            using var node = key.OpenSubKey(child);
            if (node is not null)
            {
                WalkShellBags(node, $@"{path}\{child}", sid, profile, buckets, ref visited, depth + 1);
            }
        }
    }

    /// <summary>
    /// Ярлыки и списки переходов. Здесь видно уже не папку, а сам файл, который
    /// открывали с сервера, — самое близкое к ответу «что именно смотрели».
    /// </summary>
    private static void ReadShortcuts(
        UserProfileIdentity profile,
        Dictionary<string, Bucket> buckets,
        List<string> warnings)
    {
        var recent = Path.Combine(profile.ProfilePath, "AppData", "Roaming", "Microsoft", "Windows", "Recent");
        ReadShortcutFolder(recent, profile, buckets, warnings,
            "Ярлыки последних открытых файлов",
            "Момент последней записи ярлыка — обычно последнее открытие файла");
        ReadShortcutFolder(
            Path.Combine(profile.ProfilePath, "AppData", "Roaming", "Microsoft", "Windows", "Network Shortcuts"),
            profile, buckets, warnings,
            "Ярлыки сетевых папок пользователя",
            "Момент последней записи ярлыка сетевой папки");
        ReadJumpLists(Path.Combine(recent, "AutomaticDestinations"), profile, buckets, warnings);
    }

    private static void ReadShortcutFolder(
        string directory,
        UserProfileIdentity profile,
        Dictionary<string, Bucket> buckets,
        List<string> warnings,
        string source,
        string timeMeaning)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }

        try
        {
            foreach (var file in Directory.EnumerateFiles(directory, "*.lnk", SearchOption.AllDirectories)
                         .Take(MaxShortcuts))
            {
                var link = ShellLinkParser.TryParse(file);
                var target = link?.BestTarget ?? "";
                if (!NetworkTarget.IsUncPath(target))
                {
                    continue;
                }

                AddVisit(buckets, target, new NetworkVisit
                {
                    WhenUtc = link?.WriteTimeUtc ?? File.GetLastWriteTimeUtc(file),
                    Kind = GuessFileOrFolder(target),
                    Target = target,
                    UserSid = profile.Sid,
                    ResolvedUserName = profile.ResolvedUserName,
                    Source = source,
                    TimeMeaning = timeMeaning,
                    Provenance = file
                });
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Ярлыки в {directory} прочитаны не полностью: {exception.Message}");
        }
    }

    private static void ReadJumpLists(
        string directory,
        UserProfileIdentity profile,
        Dictionary<string, Bucket> buckets,
        List<string> warnings)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }

        try
        {
            foreach (var file in Directory.EnumerateFiles(directory).Take(MaxShortcuts))
            {
                var appId = Path.GetFileNameWithoutExtension(file);
                foreach (var entry in ForensicArtifactParsers.ParseAutomaticJumpList(File.ReadAllBytes(file), appId))
                {
                    var target = entry.Link.BestTarget;
                    if (!NetworkTarget.IsUncPath(target))
                    {
                        continue;
                    }

                    AddVisit(buckets, target, new NetworkVisit
                    {
                        WhenUtc = entry.EntryTimestampUtc ?? entry.Link.WriteTimeUtc,
                        Kind = GuessFileOrFolder(target),
                        Target = target,
                        UserSid = profile.Sid,
                        ResolvedUserName = profile.ResolvedUserName,
                        Source = "Списки переходов программ",
                        TimeMeaning = "Момент обращения к файлу по записи списка переходов",
                        Provenance = $"{file}; поток {entry.StreamName}"
                    });
                }
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"Списки переходов у {profile.ResolvedUserName} прочитаны не полностью: {exception.Message}");
        }
    }

    // ---------------------------------------------------------- Служебное

    /// <summary>
    /// Ярлык хранит и файлы, и папки одинаково, а читать «открывали файл
    /// \\сервер\SOFT» неверно: SOFT — папка. Различить их можно только по
    /// расширению в конце пути, поэтому файл без расширения будет назван папкой.
    /// Ошибиться здесь безопаснее в сторону папки: она означает лишь заход, а
    /// файл — работу с содержимым.
    ///
    /// Одной точки для расширения мало: в пути «…\143.6250» после точки стоит
    /// число, и папка измерения читалась файлом. У расширения есть буквы.
    /// </summary>
    private static string GuessFileOrFolder(string target)
    {
        var extension = Path.GetExtension(target).Trim('.');
        return extension.Length is > 0 and <= 8 && extension.Any(char.IsLetter)
            ? NetworkVisitKind.File
            : NetworkVisitKind.Folder;
    }

    /// <summary>
    /// Обращение относится к узлу, который стоит в его пути: сетевая папка — к
    /// серверу, адрес страницы — к сайту. Значение, из которого узел не
    /// вытаскивается, обращением по сети не является и отбрасывается: в списке
    /// связей ему соответствовать нечему.
    /// </summary>
    private static void AddVisit(
        Dictionary<string, Bucket> buckets,
        string target,
        NetworkVisit visit,
        string account = "")
    {
        var (kind, host) = Classify(target);
        if (host.Length == 0)
        {
            return;
        }

        var bucket = Bucket.For(buckets, kind, host, () => new NetworkConnectionRecord
        {
            Kind = kind,
            Name = host,
            Account = account,
            Direction = NetworkDirection.Outgoing,
            Source = visit.Source,
            Details = kind == NetworkConnectionKind.NetworkShare
                ? NetworkConnectionExplanations.ShareServer
                : NetworkConnectionExplanations.Host,
            Provenance = visit.Provenance
        });

        bucket.Record.Account = FirstNotEmpty(bucket.Record.Account, account);
        bucket.AddVisit(visit);
    }

    /// <summary>Вид связи и узел по самому пути или адресу.</summary>
    private static (string Kind, string Host) Classify(string target)
    {
        var text = (target ?? "").Trim();
        if (NetworkTarget.IsUncPath(text))
        {
            return NetworkTarget.TryReadServer(text, out var host, out _)
                ? (NetworkConnectionKind.NetworkShare, host)
                : (NetworkConnectionKind.NetworkShare, "");
        }

        if (text.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase))
        {
            var host = NetworkTarget.HostOf(text);
            return (NetworkConnectionKind.WebSite, NetworkTarget.IsLoopback(host) ? "" : host);
        }

        return ("", "");
    }

    private sealed class Bucket
    {
        private Bucket(NetworkConnectionRecord record) => Record = record;

        public NetworkConnectionRecord Record { get; }

        public Dictionary<string, NetworkVisit> Visits { get; } = new(StringComparer.OrdinalIgnoreCase);

        public static Bucket For(
            Dictionary<string, Bucket> buckets,
            string kind,
            string name,
            Func<NetworkConnectionRecord> create)
        {
            var key = $"{kind}|{name}";
            if (!buckets.TryGetValue(key, out var bucket))
            {
                bucket = new Bucket(create());
                buckets[key] = bucket;
            }

            return bucket;
        }

        /// <summary>
        /// Один и тот же путь Windows хранит сразу в нескольких местах: и в
        /// дереве папок, и в ярлыке, и в списке переходов. В отчёте он остаётся
        /// одной строкой с самым поздним временем и числом упоминаний, иначе
        /// список превращается в перечень повторов одного действия.
        /// </summary>
        public void AddVisit(NetworkVisit visit)
        {
            var key = $"{visit.Kind}|{visit.Target}|{visit.UserSid}";
            if (!Visits.TryGetValue(key, out var existing))
            {
                visit.MentionCount = 1;
                Visits[key] = visit;
                return;
            }

            existing.MentionCount = (existing.MentionCount ?? 1) + 1;
            if (visit.WhenUtc > existing.WhenUtc)
            {
                existing.WhenUtc = visit.WhenUtc;
                existing.Provenance = visit.Provenance;
                existing.Source = visit.Source;
                existing.TimeMeaning = visit.TimeMeaning;
            }
        }
    }

    private static List<NetworkConnectionRecord> Finish(IEnumerable<Bucket> buckets)
    {
        var result = new List<NetworkConnectionRecord>();
        foreach (var bucket in buckets)
        {
            var record = bucket.Record;
            record.Visits.AddRange(bucket.Visits.Values
                .OrderByDescending(x => x.WhenUtc ?? DateTimeOffset.MinValue));

            var moments = record.Visits
                .Where(x => x.WhenUtc is not null)
                .Select(x => x.WhenUtc!.Value)
                .ToList();

            if (moments.Count > 0)
            {
                record.FirstSeenUtc = moments.Min();
                record.LastSeenUtc = moments.Max();
                record.FirstSeenProvenance = "самое раннее обращение к этому узлу по следам проводника; "
                                             + "это время записи следа, а не обязательно время обращения";
                record.LastSeenProvenance = "самое позднее обращение по следам проводника";
            }

            result.Add(record);
        }

        return result;
    }

    private static string FirstNotEmpty(params string[] values) =>
        values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "";
}
