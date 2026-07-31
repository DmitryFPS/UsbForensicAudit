using System.IO;
using Microsoft.Data.Sqlite;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class BrowserHistoryTests
{
    private static readonly UserProfileIdentity Profile =
        new("S-1-5-21-1-2-3-1001", "DESKTOP\\adm", @"C:\Users\adm");

    [Fact]
    public void Pages_of_one_site_come_together_into_one_row_with_its_own_visit_count()
    {
        using var database = ChromiumHistory.Create();
        var sites = new Dictionary<string, NetworkConnectionRecord>(StringComparer.OrdinalIgnoreCase);

        BrowserHistoryCollector.ReadChromium(database.Browser, Profile, sites);
        var result = BrowserHistoryCollector.Finish(sites.Values);

        var site = Assert.Single(result, x => x.Name == "funpay.com");
        Assert.Equal(NetworkConnectionKind.WebSite, site.Kind);
        Assert.Equal(2, site.Visits.Count(x => x.Kind == NetworkVisitKind.Site));
        Assert.Contains("страниц в истории — 2", site.DetailsText);

        var frequent = site.Visits.First(x => x.Kind == NetworkVisitKind.Site);
        Assert.Equal("https://funpay.com/orders/", frequent.Target);
        Assert.Equal(30, frequent.RepeatCount);
        Assert.Equal("Обращений по счёту источника: 30", frequent.CountText);
    }

    /// <summary>
    /// Адрес в отчёте должен открываться. Строка запроса — часть адреса, и её
    /// потеря делает адрес другим: «…/thank-you?dv=win» без вопросительного
    /// знака ведёт в никуда.
    /// </summary>
    [Fact]
    public void Address_keeps_its_query_string()
    {
        using var database = ChromiumHistory.Create();
        var sites = new Dictionary<string, NetworkConnectionRecord>(StringComparer.OrdinalIgnoreCase);

        BrowserHistoryCollector.ReadChromium(database.Browser, Profile, sites);

        var visit = sites["code.visualstudio.com"].Visits
            .First(x => x.Kind == NetworkVisitKind.Site);
        Assert.Equal("https://code.visualstudio.com/thank-you?dv=win&build=stable", visit.TargetText);
    }

    [Fact]
    public void Downloaded_file_names_where_it_came_from_and_where_it_was_put()
    {
        using var database = ChromiumHistory.Create();
        var sites = new Dictionary<string, NetworkConnectionRecord>(StringComparer.OrdinalIgnoreCase);

        BrowserHistoryCollector.ReadChromium(database.Browser, Profile, sites);
        var result = BrowserHistoryCollector.Finish(sites.Values);

        var site = Assert.Single(result, x => x.Name == "td.telegram.org");
        var download = Assert.Single(site.Visits, x => x.Kind == NetworkVisitKind.Download);
        Assert.Equal("https://td.telegram.org/tx64/tsetup.exe", download.Target);
        Assert.Contains(@"сохранён как C:\Users\adm\Downloads\tsetup.exe", download.TitleText);
        Assert.Contains("размер 51,7 МБ", download.TitleText);
        Assert.Contains("со страницы https://telegram.org/desktop", download.TitleText);
        Assert.Equal("Скачивали файл", download.KindText);
        Assert.Contains("скачанных файлов — 1", site.DetailsText);
    }

    /// <summary>
    /// Поисковый запрос объясняет, зачем пошли на страницу, и в отчёте он нужен
    /// рядом с ней.
    /// </summary>
    [Fact]
    public void Search_words_are_written_next_to_the_page_they_led_to()
    {
        using var database = ChromiumHistory.Create();
        var sites = new Dictionary<string, NetworkConnectionRecord>(StringComparer.OrdinalIgnoreCase);

        BrowserHistoryCollector.ReadChromium(database.Browser, Profile, sites);

        var visit = sites["www.bing.com"].Visits.First();
        Assert.Contains("искали: как скрыть следы флешки", visit.TitleText);
    }

    /// <summary>
    /// Служебные страницы браузера наружу не ведут, и связью с внешним миром они
    /// не являются.
    /// </summary>
    [Fact]
    public void Internal_pages_of_the_browser_are_not_taken_for_network_connections()
    {
        using var database = ChromiumHistory.Create();
        var sites = new Dictionary<string, NetworkConnectionRecord>(StringComparer.OrdinalIgnoreCase);

        BrowserHistoryCollector.ReadChromium(database.Browser, Profile, sites);

        Assert.DoesNotContain(sites.Keys, x => x.Contains("settings", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(sites.Keys, x => x.Contains("newtab", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Обращение к службе на самой машине наружу не выходит, и назвать его
    /// выходом в сеть нельзя. Но и выбросить его нельзя: по нему видно, какие
    /// службы на машине работали.
    /// </summary>
    [Fact]
    public void Address_of_the_machine_itself_is_kept_and_named_as_such()
    {
        using var database = ChromiumHistory.Create();
        var sites = new Dictionary<string, NetworkConnectionRecord>(StringComparer.OrdinalIgnoreCase);

        BrowserHistoryCollector.ReadChromium(database.Browser, Profile, sites);

        Assert.Contains("на самой машине", sites["127.0.0.1"].DetailsText);
    }

    [Fact]
    public void First_and_last_visit_come_from_the_records_of_the_browser()
    {
        using var database = ChromiumHistory.Create();
        var sites = new Dictionary<string, NetworkConnectionRecord>(StringComparer.OrdinalIgnoreCase);

        BrowserHistoryCollector.ReadChromium(database.Browser, Profile, sites);
        var result = BrowserHistoryCollector.Finish(sites.Values);

        var site = Assert.Single(result, x => x.Name == "funpay.com");
        Assert.Equal(new DateTimeOffset(2026, 7, 20, 8, 0, 0, TimeSpan.Zero), site.FirstSeenUtc);
        Assert.Equal(new DateTimeOffset(2026, 7, 31, 9, 25, 0, TimeSpan.Zero), site.LastSeenUtc);
        Assert.Contains("браузера", site.FirstSeenProvenance);
    }

    [Fact]
    public void History_of_firefox_is_read_by_its_own_tables_and_its_own_count_of_time()
    {
        using var database = FirefoxHistory.Create();
        var sites = new Dictionary<string, NetworkConnectionRecord>(StringComparer.OrdinalIgnoreCase);

        BrowserHistoryCollector.ReadFirefox(database.Browser, Profile, sites);

        var visit = Assert.Single(sites["example.org"].Visits);
        Assert.Equal(new DateTimeOffset(2026, 7, 30, 12, 0, 0, TimeSpan.Zero), visit.WhenUtc);
        Assert.Equal(7, visit.RepeatCount);
    }

    [Theory]
    [InlineData(512L, "512 Б")]
    [InlineData(2048L, "2 КБ")]
    [InlineData(54229584L, "51,7 МБ")]
    [InlineData(643194800L, "613,4 МБ")]
    [InlineData(3221225472L, "3 ГБ")]
    public void Size_of_the_file_is_written_in_words(long bytes, string expected) =>
        Assert.Equal(expected, FileSizeText.Describe(bytes));

    [Fact]
    public void Time_of_chromium_counts_from_the_year_1601()
    {
        // Значение взято из истории на проверяемой машине.
        Assert.Equal(
            new DateTimeOffset(2026, 7, 31, 12, 31, 8, TimeSpan.Zero),
            WebKitTime.FromMicroseconds(13429974668000000));
        Assert.Null(WebKitTime.FromMicroseconds(0));
    }

    private sealed class ChromiumHistory : IDisposable
    {
        private readonly string _path;

        private ChromiumHistory(string path, BrowserProfile browser)
        {
            _path = path;
            Browser = browser;
        }

        public BrowserProfile Browser { get; }

        public static ChromiumHistory Create()
        {
            var path = Path.Combine(Path.GetTempPath(), $"History-{Guid.NewGuid():N}");
            using var connection = new SqliteConnection($"Data Source={path}");
            connection.Open();
            Execute(connection, """
                create table urls (id integer primary key, url text, title text,
                    visit_count integer, last_visit_time integer);
                create table visits (id integer primary key, url integer, visit_time integer);
                create table downloads (id integer primary key, target_path text, tab_url text,
                    total_bytes integer, start_time integer);
                create table downloads_url_chains (id integer, chain_index integer, url text);
                create table keyword_search_terms (keyword_id integer, url_id integer, term text);
                """);

            // Время Chromium: микросекунды от 1 января 1601 года.
            var orders = Moment(new DateTime(2026, 7, 31, 9, 25, 0, DateTimeKind.Utc));
            var main = Moment(new DateTime(2026, 7, 25, 10, 0, 0, DateTimeKind.Utc));
            var earliest = Moment(new DateTime(2026, 7, 20, 8, 0, 0, DateTimeKind.Utc));
            var search = Moment(new DateTime(2026, 7, 27, 7, 43, 21, DateTimeKind.Utc));

            Execute(connection, $"""
                insert into urls values
                    (1, 'https://funpay.com/orders/', 'Мои покупки / FunPay', 30, {orders}),
                    (2, 'https://funpay.com/', 'FunPay — биржа игровых ценностей', 20, {main}),
                    (3, 'https://www.bing.com/search?q=flash', 'flash — Поиск', 1, {search}),
                    (4, 'https://code.visualstudio.com/thank-you?dv=win&build=stable', 'Thanks', 1, {main}),
                    (5, 'edge://settings/profiles', 'Параметры', 4, {main}),
                    (6, 'http://127.0.0.1:5173/admin/agent-search', 'Поиск', 3, {main});
                insert into visits values
                    (1, 1, {earliest}), (2, 1, {orders}), (3, 2, {main});
                insert into keyword_search_terms values (1, 3, 'как скрыть следы флешки');
                insert into downloads values
                    (7, 'C:\Users\adm\Downloads\tsetup.exe', 'https://telegram.org/desktop',
                     54229584, {main});
                insert into downloads_url_chains values
                    (7, 0, 'https://telegram.org/desktop'),
                    (7, 1, 'https://td.telegram.org/tx64/tsetup.exe');
                """);

            return new ChromiumHistory(path, new BrowserProfile("Проверочный браузер", path, false));
        }

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            File.Delete(_path);
        }

        private static long Moment(DateTime value) =>
            (long)(value - new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMicroseconds;

        private static void Execute(SqliteConnection connection, string sql)
        {
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }
    }

    private sealed class FirefoxHistory : IDisposable
    {
        private readonly string _path;

        private FirefoxHistory(string path, BrowserProfile browser)
        {
            _path = path;
            Browser = browser;
        }

        public BrowserProfile Browser { get; }

        public static FirefoxHistory Create()
        {
            var path = Path.Combine(Path.GetTempPath(), $"places-{Guid.NewGuid():N}.sqlite");
            using var connection = new SqliteConnection($"Data Source={path}");
            connection.Open();
            using var command = connection.CreateCommand();

            // Время Firefox: микросекунды от 1 января 1970 года.
            var when = (long)(new DateTime(2026, 7, 30, 12, 0, 0, DateTimeKind.Utc) - DateTime.UnixEpoch)
                .TotalMicroseconds;
            command.CommandText = $"""
                create table moz_places (id integer primary key, url text, title text,
                    visit_count integer, last_visit_date integer, hidden integer);
                create table moz_historyvisits (id integer primary key, place_id integer,
                    visit_date integer);
                insert into moz_places values
                    (1, 'https://example.org/page', 'Страница', 7, {when}, 0),
                    (2, 'about:config', 'Настройки', 1, {when}, 0),
                    (3, 'https://hidden.example/frame', 'Кадр', 1, {when}, 1);
                insert into moz_historyvisits values (1, 1, {when});
                """;
            command.ExecuteNonQuery();

            return new FirefoxHistory(path, new BrowserProfile("Проверочный Firefox", path, true));
        }

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            File.Delete(_path);
        }
    }
}
