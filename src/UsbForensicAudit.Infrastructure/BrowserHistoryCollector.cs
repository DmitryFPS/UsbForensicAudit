using System.Data;
using System.IO;
using Microsoft.Data.Sqlite;

namespace UsbForensicAudit;

/// <summary>
/// Куда ходили в сети через браузер: адреса страниц, что искали, что скачивали.
///
/// Журналы Windows отвечают, к какой сети машина была подключена; история
/// браузера отвечает, куда по этой сети ходили. Для проверки важнее всего
/// загрузки: у скачанного файла есть и адрес, откуда он пришёл, и путь, куда
/// его положили, — это прямая запись о появлении данных на машине.
///
/// История лежит в базе, которую браузер держит открытой, поэтому база
/// копируется во временную папку и читается только для чтения: правка чужого
/// артефакта в проверке недопустима.
/// </summary>
internal sealed class BrowserHistoryCollector : INetworkArtifactCollector
{
    /// <summary>Сколько страниц одного сайта показывать: у частых сайтов их сотни.</summary>
    private const int MaxPagesPerSite = 40;

    private const int MaxRowsPerProfile = 20000;

    public string ProgressMessage => "Чтение истории браузеров: адреса, поиск и загрузки...";

    public bool ShouldRun => true;

    public NetworkArtifactSet Collect(List<string> warnings)
    {
        var sites = new Dictionary<string, NetworkConnectionRecord>(StringComparer.OrdinalIgnoreCase);
        var profiles = UserArtifactCollector.ResolveProfiles(warnings);
        var read = 0;

        foreach (var profile in profiles.Values.Where(x => Directory.Exists(x.ProfilePath)).Take(256))
        {
            foreach (var browser in BrowserProfiles.Find(profile.ProfilePath))
            {
                try
                {
                    read++;
                    if (browser.IsFirefox)
                    {
                        ReadFirefox(browser, profile, sites);
                    }
                    else
                    {
                        ReadChromium(browser, profile, sites);
                    }
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    warnings.Add($"История {browser.Title} у {profile.ResolvedUserName} прочитана не "
                                 + $"полностью: {exception.Message}");
                }
            }
        }

        var evidence = new List<EvidenceRecord>();
        if (read == 0)
        {
            evidence.Add(NoBrowsers());
        }

        return new NetworkArtifactSet(Finish(sites.Values), evidence);
    }

    // ------------------------------------------------- Браузеры на движке Chromium

    /// <summary>
    /// История браузеров на движке Chromium: Edge, Chrome, Яндекс, Brave, Opera,
    /// Vivaldi. Таблицы у них одни и те же, различаются только папки.
    /// </summary>
    internal static void ReadChromium(
        BrowserProfile browser,
        UserProfileIdentity profile,
        Dictionary<string, NetworkConnectionRecord> sites)
    {
        using var copy = new TemporaryDatabaseCopy(browser.DatabasePath);
        using var connection = copy.Open();

        var searches = ReadSearchTerms(connection);
        var rows = 0;

        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                select u.id, u.url, u.title, u.visit_count, u.last_visit_time,
                       (select min(v.visit_time) from visits v where v.url = u.id)
                from urls u
                order by u.visit_count desc
                """;

            using var reader = command.ExecuteReader();
            while (reader.Read() && rows++ < MaxRowsPerProfile)
            {
                var url = reader.GetString(1);
                var record = SiteOf(sites, url, browser, out var host);
                if (record is null)
                {
                    continue;
                }

                var id = reader.GetInt64(0);
                var title = reader.IsDBNull(2) ? "" : reader.GetString(2);
                var searched = searches.TryGetValue(id, out var term) ? term : "";

                record.Visits.Add(new NetworkVisit
                {
                    WhenUtc = WebKitTime.Read(reader, 4),
                    Kind = NetworkVisitKind.Site,
                    Target = url,
                    Title = DescribePage(title, searched),
                    UserSid = profile.Sid,
                    ResolvedUserName = profile.ResolvedUserName,
                    RepeatCount = reader.IsDBNull(3) ? null : reader.GetInt32(3),
                    Source = $"История браузера {browser.Title}",
                    TimeMeaning = "Время последнего открытия страницы по записи браузера",
                    Provenance = $"{browser.DatabasePath}; таблица urls, строка {id}"
                });

                var earliest = WebKitTime.Read(reader, 5);
                if (earliest is not null && (record.FirstSeenUtc is null || earliest < record.FirstSeenUtc))
                {
                    record.FirstSeenUtc = earliest;
                }

                _ = host;
            }
        }

        ReadChromiumDownloads(connection, browser, profile, sites);
    }

    /// <summary>
    /// Скачанные файлы. Запись загрузки — самое весомое, что есть в истории:
    /// в ней записаны и адрес, откуда файл пришёл, и место, куда он лёг, и его
    /// размер.
    /// </summary>
    private static void ReadChromiumDownloads(
        SqliteConnection connection,
        BrowserProfile browser,
        UserProfileIdentity profile,
        Dictionary<string, NetworkConnectionRecord> sites)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            select d.id, d.target_path, d.tab_url, d.total_bytes, d.start_time,
                   (select c.url from downloads_url_chains c
                     where c.id = d.id order by c.chain_index desc limit 1)
            from downloads d
            order by d.start_time desc
            """;

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var fileUrl = reader.IsDBNull(5) ? "" : reader.GetString(5);
            var pageUrl = reader.IsDBNull(2) ? "" : reader.GetString(2);
            var address = fileUrl.Length > 0 ? fileUrl : pageUrl;
            var record = SiteOf(sites, address, browser, out _);
            if (record is null)
            {
                continue;
            }

            var savedTo = reader.IsDBNull(1) ? "" : reader.GetString(1);
            var size = reader.IsDBNull(3) ? 0L : reader.GetInt64(3);

            record.Visits.Add(new NetworkVisit
            {
                WhenUtc = WebKitTime.Read(reader, 4),
                Kind = NetworkVisitKind.Download,
                Target = address,
                Title = DescribeDownload(savedTo, size, pageUrl, fileUrl),
                UserSid = profile.Sid,
                ResolvedUserName = profile.ResolvedUserName,
                Source = $"История загрузок браузера {browser.Title}",
                TimeMeaning = "Время начала загрузки файла",
                Provenance = $"{browser.DatabasePath}; таблица downloads, строка {reader.GetInt64(0)}"
            });
        }
    }

    /// <summary>
    /// Что искали. Поисковый запрос — не адрес страницы, но именно он объясняет,
    /// зачем на страницу пошли, поэтому он становится подписью к ней.
    /// </summary>
    private static Dictionary<long, string> ReadSearchTerms(SqliteConnection connection)
    {
        var result = new Dictionary<long, string>();
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = "select url_id, term from keyword_search_terms";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var term = reader.IsDBNull(1) ? "" : reader.GetString(1);
                if (term.Length > 0)
                {
                    result[reader.GetInt64(0)] = term;
                }
            }
        }
        catch (SqliteException)
        {
            // Таблицы поисковых запросов в базе может не быть: она появилась не сразу
            // и в сборках без поисковой строки отсутствует. Молчание здесь безопасно —
            // теряется только подпись к странице.
        }

        return result;
    }

    // ------------------------------------------------------------------ Firefox

    /// <summary>
    /// История Firefox лежит в других таблицах и в другом счёте времени:
    /// микросекунды считаются не от 1601 года, как в Chromium, а от 1970.
    /// </summary>
    internal static void ReadFirefox(
        BrowserProfile browser,
        UserProfileIdentity profile,
        Dictionary<string, NetworkConnectionRecord> sites)
    {
        using var copy = new TemporaryDatabaseCopy(browser.DatabasePath);
        using var connection = copy.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            select p.id, p.url, p.title, p.visit_count, p.last_visit_date,
                   (select min(v.visit_date) from moz_historyvisits v where v.place_id = p.id)
            from moz_places p
            where p.hidden = 0
            order by p.visit_count desc
            """;

        var rows = 0;
        using var reader = command.ExecuteReader();
        while (reader.Read() && rows++ < MaxRowsPerProfile)
        {
            var url = reader.GetString(1);
            var record = SiteOf(sites, url, browser, out _);
            if (record is null)
            {
                continue;
            }

            var id = reader.GetInt64(0);
            record.Visits.Add(new NetworkVisit
            {
                WhenUtc = UnixMicroseconds.Read(reader, 4),
                Kind = NetworkVisitKind.Site,
                Target = url,
                Title = DescribePage(reader.IsDBNull(2) ? "" : reader.GetString(2), ""),
                UserSid = profile.Sid,
                ResolvedUserName = profile.ResolvedUserName,
                RepeatCount = reader.IsDBNull(3) ? null : reader.GetInt32(3),
                Source = $"История браузера {browser.Title}",
                TimeMeaning = "Время последнего открытия страницы по записи браузера",
                Provenance = $"{browser.DatabasePath}; таблица moz_places, строка {id}"
            });

            var earliest = UnixMicroseconds.Read(reader, 5);
            if (earliest is not null && (record.FirstSeenUtc is null || earliest < record.FirstSeenUtc))
            {
                record.FirstSeenUtc = earliest;
            }
        }
    }

    // ---------------------------------------------------------------- Служебное

    /// <summary>
    /// Строка сайта, к которой относится обращение. Страницы одного узла
    /// собираются в одну строку: иначе вкладка превращается в перечень тысячи
    /// адресов, среди которых не видно ни одного сервера.
    /// </summary>
    private static NetworkConnectionRecord? SiteOf(
        Dictionary<string, NetworkConnectionRecord> sites,
        string url,
        BrowserProfile browser,
        out string host)
    {
        host = "";
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            && !url.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase))
        {
            // Служебные адреса браузера вида «edge://settings» наружу не ведут.
            return null;
        }

        host = NetworkTarget.HostOf(url);
        if (host.Length == 0)
        {
            return null;
        }

        if (sites.TryGetValue(host, out var existing))
        {
            if (!existing.Sources.Contains(browser.Title))
            {
                existing.Sources.Add($"История браузера {browser.Title}");
            }

            return existing;
        }

        var record = new NetworkConnectionRecord
        {
            Kind = NetworkConnectionKind.WebSite,
            Name = host,
            Direction = NetworkDirection.Outgoing,
            Source = $"История браузера {browser.Title}",
            Details = NetworkTarget.IsLoopback(host)
                ? "Служба на самой машине: адрес указывает на неё же, и наружу такое обращение не "
                  + "выходит. В отчёте оно оставлено потому, что показывает, какие службы на машине "
                  + "работали и что через них делали"
                : "Сайт, который открывали в браузере",
            Provenance = browser.DatabasePath
        };

        sites[host] = record;
        return record;
    }

    private static string DescribePage(string title, string searched)
    {
        var parts = new List<string>();
        var text = (title ?? "").Trim();
        if (text.Length > 0)
        {
            parts.Add(text);
        }

        if (!string.IsNullOrWhiteSpace(searched))
        {
            parts.Add($"искали: {searched.Trim()}");
        }

        return string.Join("; ", parts);
    }

    private static string DescribeDownload(string savedTo, long size, string pageUrl, string fileUrl)
    {
        var parts = new List<string>
        {
            savedTo.Length > 0 ? $"сохранён как {savedTo}" : "куда сохранён, браузер не записал"
        };

        if (size > 0)
        {
            parts.Add($"размер {FileSizeText.Describe(size)}");
        }

        if (fileUrl.Length > 0 && pageUrl.Length > 0
            && !pageUrl.Equals(fileUrl, StringComparison.OrdinalIgnoreCase))
        {
            parts.Add($"со страницы {pageUrl}");
        }

        return string.Join(", ", parts);
    }

    /// <summary>
    /// Сводит собранное по сайтам: у каждого сайта остаются самые частые
    /// страницы, а загрузки не сокращаются никогда — это записи о появлении
    /// файлов на машине.
    /// </summary>
    internal static List<NetworkConnectionRecord> Finish(IEnumerable<NetworkConnectionRecord> sites)
    {
        var result = new List<NetworkConnectionRecord>();
        foreach (var record in sites)
        {
            var downloads = record.Visits.Where(x => x.Kind == NetworkVisitKind.Download).ToList();
            var pages = record.Visits.Where(x => x.Kind != NetworkVisitKind.Download)
                .OrderByDescending(x => x.RepeatCount ?? 1)
                .ThenByDescending(x => x.WhenUtc ?? DateTimeOffset.MinValue)
                .ToList();

            var shown = pages.Take(MaxPagesPerSite).ToList();
            var moments = record.Visits.Where(x => x.WhenUtc is not null)
                .Select(x => x.WhenUtc!.Value).ToList();

            record.Visits = [.. downloads, .. shown];
            record.Details = BuildDetails(record.Details, pages.Count, shown.Count, downloads);

            if (moments.Count > 0)
            {
                record.FirstSeenUtc = record.FirstSeenUtc is null
                    ? moments.Min()
                    : new[] { record.FirstSeenUtc.Value, moments.Min() }.Min();
                record.LastSeenUtc = moments.Max();
                record.FirstSeenProvenance = "самое раннее посещение по записям браузера";
                record.LastSeenProvenance = "самое позднее посещение по записям браузера";
            }

            result.Add(record);
        }

        return result;
    }

    private static string BuildDetails(
        string details, int pages, int shown, List<NetworkVisit> downloads)
    {
        var parts = new List<string> { details };
        parts.Add(shown < pages
            ? $"страниц в истории — {pages}, показаны {shown} самых частых"
            : $"страниц в истории — {pages}");

        if (downloads.Count > 0)
        {
            parts.Add($"скачанных файлов — {downloads.Count}; все они перечислены полностью");
        }

        return string.Join(". ", parts.Where(x => x.Length > 0));
    }

    private static EvidenceRecord NoBrowsers() => new()
    {
        TimestampUtc = DateTimeOffset.UtcNow,
        Source = "История браузеров",
        EvidenceCategory = "Полнота источника",
        EvidenceStrength = "Context",
        Confidence = "High",
        CanEstablishConnectionDate = false,
        Summary = "Баз истории браузеров на машине не найдено.",
        UserExplanation = "Проверены папки Edge, Chrome, Яндекс Браузера, Brave, Opera, Vivaldi и "
                          + "Firefox во всех профилях пользователей. Ни одной базы истории нет: либо "
                          + "браузерами не пользовались, либо историю удалили вместе с профилем, либо "
                          + "работали в браузере, который здесь не проверяется.",
        Provenance = "Профили пользователей: AppData\\Local и AppData\\Roaming"
    };
}

/// <summary>Размер файла словами: «54,2 МБ» вместо «54229584».</summary>
internal static class FileSizeText
{
    internal static string Describe(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} Б",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} КБ",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.#} МБ",
        _ => $"{bytes / (1024.0 * 1024 * 1024):0.##} ГБ"
    };
}

/// <summary>Время Chromium: микросекунды от 1 января 1601 года по Гринвичу.</summary>
internal static class WebKitTime
{
    internal static DateTimeOffset? Read(IDataRecord reader, int index)
    {
        if (reader.IsDBNull(index))
        {
            return null;
        }

        return FromMicroseconds(reader.GetInt64(index));
    }

    internal static DateTimeOffset? FromMicroseconds(long value)
    {
        if (value <= 0)
        {
            return null;
        }

        try
        {
            return new DateTimeOffset(new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc))
                .AddTicks(value * 10);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}

/// <summary>Время Firefox: микросекунды от 1 января 1970 года по Гринвичу.</summary>
internal static class UnixMicroseconds
{
    internal static DateTimeOffset? Read(IDataRecord reader, int index)
    {
        if (reader.IsDBNull(index))
        {
            return null;
        }

        var value = reader.GetInt64(index);
        if (value <= 0)
        {
            return null;
        }

        try
        {
            return DateTimeOffset.UnixEpoch.AddTicks(value * 10);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}
