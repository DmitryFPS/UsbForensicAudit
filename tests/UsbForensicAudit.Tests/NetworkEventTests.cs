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
}
