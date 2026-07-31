using System;
using System.IO;
using System.Linq;
using ClosedXML.Excel;
using Microsoft.Data.Sqlite;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Сетевые связи должны доходить до всех отчётов и до хранилища. Отчёт об одних
/// флешках создаёт впечатление, что других путей выноса данных не было, а
/// сетевая папка выносит файлы не хуже носителя.
/// </summary>
public class NetworkReportTests
{
    private static readonly DateTimeOffset Moment = new(2026, 3, 14, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Html_has_a_section_with_connections_and_where_they_led()
    {
        var html = ForensicReportBuilder.BuildHtml(ResultWithNetwork());

        Assert.Contains("Сетевые подключения и куда по ним ходили", html);
        Assert.Contains("Сетевая папка", html);
        Assert.Contains("20.20.20.76", html);
        Assert.Contains(@"\\20.20.20.76\SOFT\Отчёты", html);
        Assert.Contains("Куда ходили", html);
        Assert.Contains("Сеансы связи", html);
    }

    [Fact]
    public void Html_summary_counts_the_connections_that_could_carry_data_away()
    {
        var html = ForensicReportBuilder.BuildHtml(ResultWithNetwork());

        Assert.Contains("Найдено связей: 2", html);
        Assert.Contains("данные могли уйти с машины: 1", html);
    }

    [Fact]
    public void Html_names_the_source_of_every_network_date()
    {
        var html = ForensicReportBuilder.BuildHtml(ResultWithNetwork());

        Assert.Contains("Реестр Windows, список сетей", html);
    }

    [Fact]
    public void Excel_has_sheets_for_connections_visits_and_sessions()
    {
        var directory = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var path = new ReportService().CreateExcel(ResultWithNetwork(), directory);
            using var workbook = new XLWorkbook(path);

            var connections = Values(workbook.Worksheet("Сетевые подключения"));
            Assert.Contains(connections, x => x.Contains("20.20.20.76"));
            Assert.Contains(connections, x => x.Contains("Сеть Wi-Fi"));

            var visits = Values(workbook.Worksheet("Куда ходили по сети"));
            Assert.Contains(visits, x => x.Contains(@"\\20.20.20.76\SOFT\Отчёты"));
            Assert.Contains(visits, x => x.Contains("Что означает время"));

            var sessions = Values(workbook.Worksheet("Сеансы связи"));
            Assert.Contains(sessions, x => x.Contains("Подключение к сети Wi-Fi установлено"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Full_pdf_is_generated_with_the_network_section()
    {
        var directory = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var path = new ReportService().CreatePdf(ResultWithNetwork(), directory);

            Assert.True(File.Exists(path));
            Assert.True(new FileInfo(path).Length > 1000);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Brief_pdf_is_generated_with_the_network_counts()
    {
        var directory = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var path = new ReportService().CreateBriefPdf(ResultWithNetwork(), directory);

            Assert.True(File.Exists(path));
            Assert.True(new FileInfo(path).Length > 1000);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Связь без сохранённой истории обращений и сеансов бесполезна: повторно
    /// открыть отчёт по базе — то же самое, что открыть его сразу после
    /// сканирования.
    /// </summary>
    [Fact]
    public void Storage_keeps_the_connection_with_its_visits_and_sessions()
    {
        var directory = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var storage = new AuditStorage(directory);
            var result = ResultWithNetwork();
            storage.Save(result);

            var loaded = storage.Load(result.SessionId);

            Assert.NotNull(loaded);
            var share = loaded!.NetworkConnections
                .Single(x => x.Kind == NetworkConnectionKind.NetworkShare);
            Assert.Equal("20.20.20.76", share.Name);
            Assert.Equal(@"\\20.20.20.76\SOFT\Отчёты", share.Visits.Single().Target);
            Assert.Equal("Сеть Wi-Fi", loaded.NetworkConnections
                .Single(x => x.Kind == NetworkConnectionKind.WiFi).KindText);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Jsonl_keeps_the_network_connections_in_the_hash_chain()
    {
        var directory = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var storage = new AuditStorage(directory);
            storage.Save(ResultWithNetwork());

            var lines = File.ReadAllLines(storage.JsonlPath);

            Assert.Contains(lines, x => x.Contains("NetworkConnectionRecord"));
            Assert.Contains(lines, x => x.Contains("20.20.20.76"));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string[] Values(IXLWorksheet sheet) =>
        sheet.CellsUsed().Select(x => x.GetString()).ToArray();

    private static AuditResult ResultWithNetwork()
    {
        var result = new AuditResult
        {
            ComputerName = "Тестовый ПК",
            StartedAtUtc = Moment,
            FinishedAtUtc = Moment.AddMinutes(2)
        };

        result.NetworkConnections.Add(new NetworkConnectionRecord
        {
            Kind = NetworkConnectionKind.NetworkShare,
            Name = "20.20.20.76",
            Address = @"\\20.20.20.76",
            Direction = NetworkDirection.Outgoing,
            FirstSeenUtc = Moment.AddDays(-10),
            FirstSeenProvenance = "Журнал SMBClient/Connectivity, событие 30800",
            LastSeenUtc = Moment,
            LastSeenProvenance = "Журнал SMBClient/Connectivity, событие 30800",
            Details = NetworkConnectionExplanations.ShareServer,
            Source = "Event Log SMBClient",
            Visits =
            [
                new NetworkVisit
                {
                    WhenUtc = Moment,
                    Kind = NetworkVisitKind.Folder,
                    Target = @"\\20.20.20.76\SOFT\Отчёты",
                    ResolvedUserName = @"ПК\ivanov",
                    TimeMeaning = "Время последней записи в дерево папок проводника",
                    Source = "Live HKU Shellbags",
                    Provenance = @"HKU\S-1-5-21-1\SOFTWARE\...\BagMRU"
                }
            ]
        });

        result.NetworkConnections.Add(new NetworkConnectionRecord
        {
            Kind = NetworkConnectionKind.WiFi,
            Name = "flash 2",
            Security = "WPA2-Personal, шифрование AES",
            Adapter = "Беспроводная сеть",
            FirstSeenUtc = Moment.AddDays(-30),
            FirstSeenProvenance = "Реестр Windows, список сетей: дата создания профиля",
            LastSeenUtc = Moment.AddHours(-1),
            LastSeenProvenance = "Реестр Windows, список сетей: дата последнего подключения",
            Source = "Registry NetworkList",
            Sessions =
            [
                new NetworkSession
                {
                    StartedUtc = Moment.AddHours(-3),
                    EndedUtc = Moment.AddHours(-1),
                    Outcome = "Подключение к сети Wi-Fi установлено (автоматически)",
                    Source = "Event Log WLAN-AutoConfig",
                    Provenance = "Microsoft-Windows-WLAN-AutoConfig/Operational, событие 8001"
                }
            ]
        });

        return result;
    }
}
