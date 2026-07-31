using System.Buffers.Binary;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Разбор значений из журналов Windows и сведение событий в сеансы. Значения
/// взяты из настоящих событий проверяемой машины.
/// </summary>
public class NetworkEventTests
{
    [Fact]
    public void Session_events_become_pairs_of_connect_and_disconnect()
    {
        var start = DateTimeOffset.Parse("2026-07-31T08:33:57Z");
        var end = DateTimeOffset.Parse("2026-07-31T09:24:02Z");

        var sessions = NetworkSessionPairing.Pair(
        [
            new NetworkSessionEvent(end, NetworkSessionRole.End, "Сеть Wi-Fi отключена", "Сеть отключена пользователем."),
            new NetworkSessionEvent(start, NetworkSessionRole.Start, "Подключение установлено")
        ]);

        var session = Assert.Single(sessions);
        Assert.Equal(start, session.StartedUtc);
        Assert.Equal(end, session.EndedUtc);
        Assert.Equal("Сеть отключена пользователем.", session.Reason);
        Assert.Equal("50 мин.", session.DurationText);
    }

    [Fact]
    public void Disconnect_without_connect_keeps_only_the_end()
    {
        var end = DateTimeOffset.Parse("2026-07-31T09:24:02Z");

        var session = Assert.Single(NetworkSessionPairing.Pair(
            [new NetworkSessionEvent(end, NetworkSessionRole.End, "Сеть отключена")]));

        Assert.Null(session.StartedUtc);
        Assert.Equal(end, session.EndedUtc);
        Assert.Equal("Начало не записано", session.StartedText);
    }

    /// <summary>
    /// Выключение питания записать отключение не даёт, поэтому сеанс без конца —
    /// обычное дело, и второй конец ему выдумывать нельзя.
    /// </summary>
    [Fact]
    public void Two_connects_in_a_row_leave_the_first_session_without_an_end()
    {
        var first = DateTimeOffset.Parse("2026-07-30T07:53:00Z");
        var second = DateTimeOffset.Parse("2026-07-31T08:33:57Z");

        var sessions = NetworkSessionPairing.Pair(
        [
            new NetworkSessionEvent(first, NetworkSessionRole.Start, "Подключение установлено"),
            new NetworkSessionEvent(second, NetworkSessionRole.Start, "Подключение установлено")
        ]);

        Assert.Equal(2, sessions.Count);
        Assert.All(sessions, x => Assert.Null(x.EndedUtc));
        Assert.Equal("Отключение не записано", sessions[0].EndedText);
    }

    [Fact]
    public void A_single_event_is_marked_as_a_moment_without_duration()
    {
        var when = DateTimeOffset.Parse("2026-07-28T09:50:27Z");

        var session = Assert.Single(NetworkSessionPairing.Pair(
        [
            new NetworkSessionEvent(when, NetworkSessionRole.Failure, "Не удалось установить сетевое подключение.")
        ]));

        Assert.True(session.IsMoment);
        Assert.Equal("Отдельное событие, сеанс не открывался", session.EndedText);
        Assert.Equal("не применимо", session.DurationText);
    }

    [Theory]
    [InlineData(@"\20.20.20.76\r0", "20.20.20.76", "r0")]
    [InlineData(@"\20.23.5.4", "20.23.5.4", "")]
    [InlineData(@"\\server01\ModulsFiles", "server01", "ModulsFiles")]
    [InlineData(@"\20.20.20.76\IPC$", "20.20.20.76", "IPC$")]
    public void Server_name_from_the_smb_log_splits_into_host_and_share(
        string value, string expectedHost, string expectedShare)
    {
        Assert.True(NetworkTarget.TryReadServer(value, out var host, out var share));
        Assert.Equal(expectedHost, host);
        Assert.Equal(expectedShare, share);
    }

    /// <summary>
    /// Вместо сервера журнал SMB нередко подставляет имя сетевого устройства или
    /// саму эту машину. Ни то, ни другое сервером не является: в списке связей
    /// появились бы «серверы» с именами драйверов.
    /// </summary>
    [Theory]
    [InlineData(@"\Device\NetBT_Tcpip_{32D27737-4100-4B12-8034-32E3B0905104}")]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("")]
    [InlineData(@"\")]
    public void Service_names_are_not_taken_for_servers(string value)
    {
        Assert.False(NetworkTarget.TryReadServer(value, out _, out _));
    }

    [Theory]
    [InlineData("IPC$", true)]
    [InlineData("C$", true)]
    [InlineData("ADMIN$", true)]
    [InlineData("ModulsFiles", false)]
    [InlineData("soft", false)]
    public void Administrative_shares_are_told_apart_from_folders(string share, bool expected)
    {
        Assert.Equal(expected, NetworkTarget.IsAdministrativeShare(share));
    }

    /// <summary>
    /// Настоящее значение RemoteAddress из события 30803: семейство адресов 23,
    /// порт 445, адрес ::1.
    /// </summary>
    [Fact]
    public void Remote_address_of_the_smb_event_turns_into_a_readable_address()
    {
        const string hex = "170001BD000000000000000000000000000000000000000100000000";

        Assert.True(NetworkEventValues.TryReadSocketAddress(hex, out var address, out var port));
        Assert.Equal("::1", address);
        Assert.Equal(445, port);
    }

    [Fact]
    public void Address_of_the_fourth_version_is_read_from_its_own_family()
    {
        // Семейство 2 (IPv4), порт 445, адрес 20.20.20.76.
        const string hex = "020001BD141414" + "4C" + "0000000000000000";

        Assert.True(NetworkEventValues.TryReadSocketAddress(hex, out var address, out var port));
        Assert.Equal("20.20.20.76", address);
        Assert.Equal(445, port);
    }

    [Theory]
    [InlineData("")]
    [InlineData("не шестнадцатеричная строка")]
    [InlineData("00000000000000000000000000000000000000000000000000000000")]
    public void An_unreadable_address_is_not_invented(string hex)
    {
        Assert.False(NetworkEventValues.TryReadSocketAddress(hex, out var address, out _));
        Assert.Equal("", address);
    }

    [Theory]
    [InlineData("3221225506", "доступ запрещён")]
    [InlineData("3221225653", "сервер не ответил за отведённое время")]
    [InlineData("0", "успешно")]
    [InlineData("-1073741790", "доступ запрещён")]
    [InlineData("0xC0000022", "доступ запрещён")]
    public void Status_code_is_told_in_words(string value, string expected)
    {
        Assert.Equal(expected, NetworkEventValues.DescribeStatus(value));
    }

    /// <summary>
    /// Незнакомому коду смысл не придумывается: он остаётся числом, по которому
    /// его можно проверить.
    /// </summary>
    [Fact]
    public void An_unknown_status_stays_a_number()
    {
        Assert.Equal("код 0xC000020C", NetworkEventValues.DescribeStatus("3221225996"));
        Assert.Equal("", NetworkEventValues.DescribeStatus(""));
    }

    [Theory]
    [InlineData("Идентификация...", true)]
    [InlineData("Неопознанная сеть", true)]
    [InlineData("Identifying...", true)]
    [InlineData("Unidentified network", true)]
    [InlineData("flash", false)]
    [InlineData("Сеть", false)]
    [InlineData("SigmaVPN", false)]
    public void Placeholder_network_names_are_recognized(string name, bool expected)
    {
        Assert.Equal(expected, NetworkTarget.IsPlaceholderName(name));
    }

    /// <summary>
    /// Номер сеанса «1» разбирается как адрес 0.0.0.1, и без проверки на точку
    /// он попадал в отчёт узлом, к которому подключались.
    /// </summary>
    /// <summary>
    /// Один и тот же путь приходит из журнала, из дерева папок проводника и из
    /// ярлыка. В отчёте он должен остаться одной строкой, иначе список читается
    /// как три разных захода в одну папку.
    /// </summary>
    [Fact]
    public void The_same_folder_from_three_sources_stays_one_row()
    {
        var connection = new NetworkConnectionRecord
        {
            Kind = NetworkConnectionKind.NetworkShare,
            Name = "20.20.20.76",
            Visits =
            [
                new NetworkVisit
                {
                    Kind = NetworkVisitKind.Folder,
                    Target = @"\\20.20.20.76\soft",
                    WhenUtc = DateTimeOffset.Parse("2026-07-28T09:25:26Z"),
                    Source = "Журнал Windows — обращения к сетевым папкам",
                    MentionCount = 4
                },
                new NetworkVisit
                {
                    Kind = NetworkVisitKind.Folder,
                    Target = @"\\20.20.20.76\SOFT",
                    WhenUtc = DateTimeOffset.Parse("2026-07-31T11:39:05Z"),
                    UserSid = "S-1-5-21-1-2-3-1001",
                    Source = "Реестр Windows — папки, открытые в проводнике",
                    MentionCount = 5
                }
            ]
        };

        var merged = Assert.Single(NetworkConnectionMerger.Merge([connection]));
        var visit = Assert.Single(merged.Visits);
        Assert.Equal(DateTimeOffset.Parse("2026-07-31T11:39:05Z"), visit.WhenUtc);
        Assert.Equal(9, visit.MentionCount);
        Assert.Equal("Следов: 9", visit.MentionCountText);
    }

    /// <summary>
    /// Разные пользователи, открывавшие одну папку, — два разных факта, и
    /// сливать их в одну строку нельзя.
    /// </summary>
    [Fact]
    public void The_same_folder_opened_by_two_accounts_stays_two_rows()
    {
        var connection = new NetworkConnectionRecord
        {
            Kind = NetworkConnectionKind.NetworkShare,
            Name = "20.20.20.76",
            Visits =
            [
                new NetworkVisit
                {
                    Kind = NetworkVisitKind.Folder,
                    Target = @"\\20.20.20.76\soft",
                    UserSid = "S-1-5-21-1-2-3-1001",
                    WhenUtc = DateTimeOffset.Parse("2026-07-31T11:39:05Z")
                },
                new NetworkVisit
                {
                    Kind = NetworkVisitKind.Folder,
                    Target = @"\\20.20.20.76\soft",
                    UserSid = "S-1-5-21-1-2-3-1002",
                    WhenUtc = DateTimeOffset.Parse("2026-07-30T08:00:00Z")
                }
            ]
        };

        var merged = Assert.Single(NetworkConnectionMerger.Merge([connection]));
        Assert.Equal(2, merged.Visits.Count);
    }

    [Theory]
    [InlineData("1", false)]
    [InlineData("20.20.20.76", true)]
    [InlineData("ЛОКАЛЬНЫЙ", false)]
    [InlineData("server01", true)]
    [InlineData("Адрес сетевого клиента: 10.0.0.5", false)]
    public void Session_numbers_are_not_taken_for_addresses(string value, bool expected)
    {
        Assert.Equal(expected, NetworkTarget.LooksLikeHost(value));
    }

    /// <summary>
    /// Путь к файлу на сервере ярлык хранит отдельной структурой сетевой ссылки.
    /// Без её разбора от такого ярлыка оставалось одно имя файла, и сказать, с
    /// какого сервера его открывали, было нельзя.
    /// </summary>
    [Fact]
    public void Shortcut_to_a_file_on_a_server_gives_the_whole_network_path()
    {
        var bytes = BuildNetworkShellLink(@"\\20.23.5.4\ModulsFiles", @"2026\result0.txt", "Z:");

        var parsed = ShellLinkParser.TryParse(bytes, "network.lnk");

        Assert.NotNull(parsed);
        Assert.Equal(@"\\20.23.5.4\ModulsFiles", parsed!.NetworkPath);
        Assert.Equal("Z:", parsed.NetworkDeviceName);
        Assert.Equal(@"\\20.23.5.4\ModulsFiles\2026\result0.txt", parsed.BestTarget);
        Assert.True(NetworkTarget.TryReadServer(parsed.BestTarget, out var host, out _));
        Assert.Equal("20.23.5.4", host);
    }

    /// <summary>
    /// Путь на диске этой машины остаётся главным: ярлык на локальный файл не
    /// должен превратиться в сетевой из-за того, что папка когда-то была
    /// подключена как диск.
    /// </summary>
    [Fact]
    public void A_local_path_stays_the_target_of_the_shortcut()
    {
        var info = new ShellLinkInfo
        {
            LocalBasePath = @"E:\Сбор",
            CommonPathSuffix = "report.txt",
            NetworkPath = @"\\server\share"
        };

        Assert.Equal(@"E:\Сбор\report.txt", info.BestTarget);
    }

    private static byte[] BuildNetworkShellLink(string netName, string suffix, string deviceName)
    {
        const int linkInfoOffset = 0x4C;
        const int headerSize = 0x1C;
        var data = new byte[1024];

        BinaryPrimitives.WriteUInt32LittleEndian(data, 0x4C);
        new byte[]
        {
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
        }.CopyTo(data, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x14, 4), 0x2);

        const int networkOffset = headerSize;
        const int netNameFieldOffset = 0x14;
        var netNameBytes = Encoding.Latin1.GetBytes(netName + "\0");
        var deviceBytes = Encoding.Latin1.GetBytes(deviceName + "\0");
        var networkSize = netNameFieldOffset + netNameBytes.Length + deviceBytes.Length;

        var network = data.AsSpan(linkInfoOffset + networkOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(network, checked((uint)networkSize));
        BinaryPrimitives.WriteUInt32LittleEndian(network.Slice(0x04, 4), 0x1);
        BinaryPrimitives.WriteUInt32LittleEndian(network.Slice(0x08, 4), netNameFieldOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(
            network.Slice(0x0C, 4), checked((uint)(netNameFieldOffset + netNameBytes.Length)));
        netNameBytes.CopyTo(data.AsSpan(linkInfoOffset + networkOffset + netNameFieldOffset));
        deviceBytes.CopyTo(data.AsSpan(linkInfoOffset + networkOffset + netNameFieldOffset + netNameBytes.Length));

        var suffixOffset = networkOffset + networkSize;
        var suffixBytes = Encoding.Latin1.GetBytes(suffix + "\0");
        suffixBytes.CopyTo(data.AsSpan(linkInfoOffset + suffixOffset));

        var info = data.AsSpan(linkInfoOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(info, checked((uint)(suffixOffset + suffixBytes.Length)));
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(0x04, 4), headerSize);
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(0x08, 4), 0x2);
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(0x14, 4), networkOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(0x18, 4), checked((uint)suffixOffset));

        Array.Resize(ref data, linkInfoOffset + suffixOffset + suffixBytes.Length);
        return data;
    }
}
