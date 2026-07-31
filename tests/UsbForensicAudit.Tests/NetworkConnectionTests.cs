using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Одна и та же сеть приходит из реестра, из подписей сетей и из журнала службы
/// автонастройки, а один и тот же сервер называется то «\\20.20.20.76\r0», то
/// «\20.20.20.76». Без сведения таких записей вкладка перечисляет артефакты, а
/// не связи, и счёт в отчёте становится втрое больше действительного.
/// </summary>
public class NetworkConnectionMergerTests
{
    [Fact]
    public void One_wifi_network_from_registry_and_event_log_becomes_one_connection()
    {
        var merged = NetworkConnectionMerger.Merge(
        [
            new NetworkConnectionRecord
            {
                Kind = NetworkConnectionKind.WiFi,
                Name = "flash",
                FirstSeenUtc = Moment("2026-07-27T06:40:00Z"),
                FirstSeenProvenance = "DateCreated из списка сетей",
                Source = "Реестр Windows — список сетей"
            },
            new NetworkConnectionRecord
            {
                Kind = NetworkConnectionKind.WiFi,
                Name = "flash",
                Security = "WPA2-Personal, AES-CCMP",
                Adapter = "Intel(R) Wi-Fi 7 BE200",
                LastSeenUtc = Moment("2026-07-31T11:33:57Z"),
                LastSeenProvenance = "Событие 8001",
                Source = "EventLog: Microsoft-Windows-WLAN-AutoConfig/Operational"
            }
        ]);

        var wifi = Assert.Single(merged);
        Assert.Equal("flash", wifi.Name);
        Assert.Equal("WPA2-Personal, AES-CCMP", wifi.Security);
        Assert.Equal("Intel(R) Wi-Fi 7 BE200", wifi.Adapter);
        Assert.Equal(Moment("2026-07-27T06:40:00Z"), wifi.FirstSeenUtc);
        Assert.Equal(Moment("2026-07-31T11:33:57Z"), wifi.LastSeenUtc);
        Assert.Equal(2, wifi.Sources.Count);
    }

    /// <summary>
    /// У одного сервера бывают десятки папок. Каждая из них — обращение внутри
    /// одной связи, а не отдельная связь: иначе один файловый сервер занимает
    /// всю вкладку и прячет остальные.
    /// </summary>
    [Fact]
    public void Folders_on_one_server_are_visits_inside_one_connection()
    {
        var merged = NetworkConnectionMerger.Merge(
        [
            Share(@"\\20.20.20.76\r0", "Реестр Windows — сетевые папки"),
            Share(@"\\20.20.20.76\r0\Отчёты", "Проводник — сохранённые папки"),
            Share(@"\\20.20.20.76", "EventLog: Microsoft-Windows-SMBClient/Operational")
        ]);

        var server = Assert.Single(merged);
        Assert.Equal(NetworkConnectionKind.NetworkShare, server.Kind);
        Assert.Equal(3, server.Visits.Count);
        Assert.Contains(@"\\20.20.20.76\r0\Отчёты", server.Visits.Select(x => x.Target));
    }

    [Fact]
    public void Pages_of_one_site_do_not_become_separate_connections()
    {
        var merged = NetworkConnectionMerger.Merge(
        [
            Site("https://mail.example.org/inbox"),
            Site("https://mail.example.org/message/17"),
            Site("https://cloud.example.org/files")
        ]);

        Assert.Equal(2, merged.Count);
        Assert.Equal(2, merged.First(x => x.Name == "mail.example.org").Visits.Count);
    }

    /// <summary>
    /// Сеанс из журнала бывает старше записи профиля в реестре. Даты связи не
    /// могут быть уже, чем её сеансы: иначе отчёт скажет «подключались с 27-го»,
    /// имея на руках сеанс от 20-го.
    /// </summary>
    [Fact]
    public void Connection_dates_widen_to_cover_its_sessions()
    {
        var merged = NetworkConnectionMerger.Merge(
        [
            new NetworkConnectionRecord
            {
                Kind = NetworkConnectionKind.WiFi,
                Name = "flash",
                FirstSeenUtc = Moment("2026-07-27T06:40:00Z"),
                LastSeenUtc = Moment("2026-07-27T07:00:00Z"),
                Sessions =
                [
                    new NetworkSession
                    {
                        StartedUtc = Moment("2026-07-20T10:00:00Z"),
                        EndedUtc = Moment("2026-07-31T12:24:02Z")
                    }
                ]
            }
        ]);

        var wifi = Assert.Single(merged);
        Assert.Equal(Moment("2026-07-20T10:00:00Z"), wifi.FirstSeenUtc);
        Assert.Equal(Moment("2026-07-31T12:24:02Z"), wifi.LastSeenUtc);
        Assert.Contains("сеанс", wifi.FirstSeenProvenance);
    }

    [Fact]
    public void The_same_visit_seen_by_two_artifacts_is_listed_once()
    {
        var when = Moment("2026-07-31T15:00:00Z");
        var merged = NetworkConnectionMerger.Merge(
        [
            new NetworkConnectionRecord
            {
                Kind = NetworkConnectionKind.NetworkShare,
                Name = "20.20.20.76",
                Address = @"\\20.20.20.76",
                Visits =
                [
                    new NetworkVisit { Kind = NetworkVisitKind.Folder, Target = @"\\20.20.20.76\r0", WhenUtc = when },
                    new NetworkVisit { Kind = NetworkVisitKind.Folder, Target = @"\\20.20.20.76\r0", WhenUtc = when }
                ]
            }
        ]);

        Assert.Single(Assert.Single(merged).Visits);
    }

    [Fact]
    public void Bluetooth_pairing_is_identified_by_its_address_not_by_a_renamed_device()
    {
        var merged = NetworkConnectionMerger.Merge(
        [
            new NetworkConnectionRecord
            {
                Kind = NetworkConnectionKind.Bluetooth,
                Name = "Наушники",
                Address = "a4:c1:38:11:22:33"
            },
            new NetworkConnectionRecord
            {
                Kind = NetworkConnectionKind.Bluetooth,
                Name = "JBL Tune",
                Address = "A4:C1:38:11:22:33"
            }
        ]);

        var pairing = Assert.Single(merged);
        Assert.Equal("Наушники", pairing.Name);
    }

    [Fact]
    public void Different_kinds_of_link_to_the_same_host_stay_separate()
    {
        var merged = NetworkConnectionMerger.Merge(
        [
            new NetworkConnectionRecord { Kind = NetworkConnectionKind.NetworkShare, Name = "20.20.20.76" },
            new NetworkConnectionRecord { Kind = NetworkConnectionKind.RemoteDesktop, Name = "20.20.20.76" }
        ]);

        Assert.Equal(2, merged.Count);
    }

    /// <summary>
    /// Сверху то, чем выносят данные и чем управляют чужой машиной; сайты — внизу,
    /// иначе одна сетевая папка потеряется среди сотни адресов.
    /// </summary>
    [Fact]
    public void Shares_are_listed_above_visited_sites()
    {
        var merged = NetworkConnectionMerger.Merge(
        [
            Site("https://example.org/page"),
            new NetworkConnectionRecord { Kind = NetworkConnectionKind.Wired, Name = "Сеть" },
            new NetworkConnectionRecord { Kind = NetworkConnectionKind.NetworkShare, Name = "20.20.20.76" }
        ]);

        Assert.Equal(NetworkConnectionKind.NetworkShare, merged[0].Kind);
        Assert.Equal(NetworkConnectionKind.WebSite, merged[^1].Kind);
    }

    private static NetworkConnectionRecord Share(string path, string source) => new()
    {
        Kind = NetworkConnectionKind.NetworkShare,
        Name = NetworkTarget.HostOf(path),
        Address = path,
        Source = source,
        Visits = [new NetworkVisit { Kind = NetworkVisitKind.Folder, Target = path, Source = source }]
    };

    private static NetworkConnectionRecord Site(string url) => new()
    {
        Kind = NetworkConnectionKind.WebSite,
        Name = NetworkTarget.HostOf(url),
        Address = url,
        Visits = [new NetworkVisit { Kind = NetworkVisitKind.Site, Target = url }]
    };

    private static DateTimeOffset Moment(string value) => DateTimeOffset.Parse(value);
}

/// <summary>
/// Читателю обещано, что в столбце «Куда подключались» будет путь или адрес, а
/// не служебная строка и не пустая клетка.
/// </summary>
public class NetworkTargetTests
{
    [Theory]
    [InlineData(@"\\20.20.20.76\r0", "20.20.20.76")]
    [InlineData(@"\\fileserver\share\folder", "fileserver")]
    [InlineData("https://mail.example.org/inbox?id=7", "mail.example.org")]
    [InlineData("20.20.20.76", "20.20.20.76")]
    public void Host_is_taken_from_a_share_path_and_from_a_web_address(string target, string expected) =>
        Assert.Equal(expected, NetworkTarget.HostOf(target));

    [Fact]
    public void Missing_address_is_stated_plainly_instead_of_an_empty_cell()
    {
        Assert.Equal("Адрес в артефакте не записан", NetworkTarget.Describe("", NetworkVisitKind.Site));
        Assert.Equal("Путь в артефакте не записан", NetworkTarget.Describe(null, NetworkVisitKind.Folder));
    }

    [Fact]
    public void Real_paths_and_addresses_are_shown_unchanged()
    {
        Assert.Equal(@"\\20.20.20.76\r0", NetworkTarget.Describe(@"\\20.20.20.76\r0", NetworkVisitKind.Folder));
        Assert.Equal("https://example.org/a", NetworkTarget.Describe("https://example.org/a", NetworkVisitKind.Site));
    }

    [Fact]
    public void Share_path_is_recognised_by_its_two_leading_separators()
    {
        Assert.True(NetworkTarget.IsUncPath(@"\\server\share"));
        Assert.False(NetworkTarget.IsUncPath(@"C:\Users"));
    }
}

public class NetworkConnectionRecordTests
{
    [Fact]
    public void Target_shows_the_name_and_the_address_together_when_both_are_known()
    {
        var record = new NetworkConnectionRecord { Name = "flash", Address = "192.168.1.1" };

        Assert.Equal("flash (192.168.1.1)", record.TargetText);
    }

    [Fact]
    public void Target_does_not_repeat_the_same_value_twice()
    {
        var record = new NetworkConnectionRecord { Name = "20.20.20.76", Address = "20.20.20.76" };

        Assert.Equal("20.20.20.76", record.TargetText);
    }

    [Fact]
    public void Connection_without_sessions_says_only_the_link_itself_is_known()
    {
        Assert.Equal("Только сам факт связи", new NetworkConnectionRecord().ActivityText);
    }

    /// <summary>
    /// Длительность по одному событию не придумывается: Windows пишет
    /// подключение и отключение отдельно, и второго может не быть вовсе.
    /// </summary>
    [Fact]
    public void Session_duration_is_not_invented_from_a_single_event()
    {
        var session = new NetworkSession { StartedUtc = DateTimeOffset.UtcNow };

        Assert.Equal("", session.DurationText);
        Assert.Equal("Отключение не записано", session.EndedText);
    }

    [Fact]
    public void Session_duration_is_shown_when_both_ends_are_known()
    {
        var session = new NetworkSession
        {
            StartedUtc = DateTimeOffset.Parse("2026-07-31T11:33:57Z"),
            EndedUtc = DateTimeOffset.Parse("2026-07-31T12:24:02Z")
        };

        Assert.Equal("50 мин.", session.DurationText);
    }

    [Theory]
    [InlineData(NetworkConnectionKind.NetworkShare, true)]
    [InlineData(NetworkConnectionKind.RemoteDesktop, true)]
    [InlineData(NetworkConnectionKind.Vpn, true)]
    [InlineData(NetworkConnectionKind.Bluetooth, true)]
    [InlineData(NetworkConnectionKind.Wired, false)]
    [InlineData(NetworkConnectionKind.WebSite, false)]
    public void Links_that_can_carry_data_off_the_machine_are_marked(string kind, bool expected) =>
        Assert.Equal(expected, new NetworkConnectionRecord { Kind = kind }.IsOutsideReach);
}

public class NetworkConnectionSummaryTests
{
    [Fact]
    public void Empty_result_does_not_claim_there_were_no_connections()
    {
        var text = NetworkConnectionSummary.Create([]).Describe();

        Assert.Contains("не найдено", text);
        Assert.Contains("не значит", text);
    }

    [Fact]
    public void Summary_names_the_kinds_and_what_could_carry_data_away()
    {
        var summary = NetworkConnectionSummary.Create(
        [
            new NetworkConnectionRecord { Kind = NetworkConnectionKind.WiFi, Name = "flash" },
            new NetworkConnectionRecord { Kind = NetworkConnectionKind.WiFi, Name = "flash 2" },
            new NetworkConnectionRecord
            {
                Kind = NetworkConnectionKind.NetworkShare,
                Name = "20.20.20.76",
                Visits = [new NetworkVisit { Target = @"\\20.20.20.76\r0" }]
            }
        ]);

        var text = summary.Describe();
        Assert.Equal(3, summary.Connections);
        Assert.Equal(1, summary.OutsideReach);
        Assert.Contains("сетей Wi-Fi: 2", text);
        Assert.Contains("серверов с сетевыми папками: 1", text);
        Assert.Contains("данные могли уйти", text);
        Assert.Contains("обращений: 1", text);
    }
}

/// <summary>
/// Цвет и человеческое название нужны каждому виду связи: вид добавили —
/// строка осталась серой и без подписи. Тесты держат перечни согласованными.
/// </summary>
public class NetworkConnectionPaletteTests
{
    [Fact]
    public void Every_kind_has_its_own_colour()
    {
        foreach (var kind in NetworkConnectionKind.All)
        {
            Assert.True(NetworkConnectionPalette.IsKnown(kind), $"нет цвета для вида связи {kind}");
        }
    }

    [Fact]
    public void Colours_are_distinct_so_kinds_stay_distinguishable()
    {
        var backgrounds = NetworkConnectionPalette.KnownGroups
            .Select(x => NetworkConnectionPalette.For(x).Background)
            .ToArray();

        Assert.Equal(backgrounds.Length, backgrounds.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Colours_are_valid_hex_values()
    {
        foreach (var kind in NetworkConnectionPalette.KnownGroups)
        {
            var colors = NetworkConnectionPalette.For(kind);
            Assert.Matches("^#[0-9A-Fa-f]{6}$", colors.Background);
            Assert.Matches("^#[0-9A-Fa-f]{6}$", colors.Foreground);
        }
    }

    [Fact]
    public void Unknown_kind_is_painted_as_unparsed_and_does_not_crash_the_grid()
    {
        Assert.Equal(NetworkConnectionPalette.For(NetworkConnectionKind.Unknown),
            NetworkConnectionPalette.For("СовершенноНовыйВидСвязи"));
        Assert.NotNull(NetworkConnectionPalette.For(null).Background);
        Assert.NotNull(NetworkConnectionPalette.For("").Foreground);
    }

    [Fact]
    public void Every_kind_and_visit_has_a_plain_russian_name()
    {
        foreach (var kind in NetworkConnectionKind.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(NetworkConnectionKind.Describe(kind)));
        }

        foreach (var kind in new[]
                 {
                     NetworkVisitKind.Folder, NetworkVisitKind.File, NetworkVisitKind.MappedDrive,
                     NetworkVisitKind.TypedPath, NetworkVisitKind.RememberedShare, NetworkVisitKind.Site,
                     NetworkVisitKind.Download, NetworkVisitKind.Host, NetworkVisitKind.Unknown
                 })
        {
            Assert.False(string.IsNullOrWhiteSpace(NetworkVisitKind.Describe(kind)));
        }
    }

    [Fact]
    public void Every_kind_has_its_own_place_in_the_order()
    {
        var ranks = NetworkConnectionKind.All.Select(NetworkConnectionKind.Rank).ToArray();

        Assert.Equal(ranks.Length, ranks.Distinct().Count());
    }

    /// <summary>
    /// Сотни сайтов не должны прятать одну сетевую папку, куда ушли файлы,
    /// поэтому сверху стоит то, чем данные выносят.
    /// </summary>
    [Fact]
    public void Rows_of_the_tab_put_what_carries_data_out_on_top()
    {
        var connections = new List<NetworkConnectionRecord>
        {
            new() { Kind = NetworkConnectionKind.WebSite, Name = "example.org" },
            new() { Kind = NetworkConnectionKind.Wired, Name = "Сеть" },
            new() { Kind = NetworkConnectionKind.NetworkShare, Name = "20.20.20.76" },
            new() { Kind = NetworkConnectionKind.WiFi, Name = "flash" }
        };

        var ordered = MainViewModel.OrderNetworkConnections(connections).ToList();

        Assert.Equal("20.20.20.76", ordered[0].Name);
        Assert.Equal("flash", ordered[1].Name);
        Assert.Equal("example.org", ordered[^1].Name);
    }

    /// <summary>
    /// Дата без указания источника в проверке ничего не стоит, поэтому в
    /// перечне сведений она идёт вместе с ним.
    /// </summary>
    [Fact]
    public void Facts_about_a_connection_name_the_source_of_every_date()
    {
        var record = new NetworkConnectionRecord
        {
            Kind = NetworkConnectionKind.WiFi,
            Name = "flash 2",
            FirstSeenUtc = new DateTimeOffset(2026, 7, 27, 10, 36, 2, TimeSpan.Zero),
            FirstSeenProvenance = "DateCreated в списке сетей реестра",
            LastSeenUtc = new DateTimeOffset(2026, 7, 31, 9, 23, 47, TimeSpan.Zero)
        };

        var rows = NetworkConnectionFacts.Rows(record).ToDictionary(x => x.Name, x => x.Value);

        Assert.Contains("DateCreated в списке сетей реестра", rows["Первое подключение"]);
        Assert.Contains("31.07.2026", rows["Последнее подключение"]);
        Assert.Equal("Сеть Wi-Fi", rows["Как связывались"]);
        Assert.Equal("Учётной записи в записях нет", rows["Учётная запись"]);
        Assert.All(rows.Values, value => Assert.False(string.IsNullOrWhiteSpace(value)));
    }
}
