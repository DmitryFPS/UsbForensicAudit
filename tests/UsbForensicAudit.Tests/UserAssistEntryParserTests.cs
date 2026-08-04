using System.Buffers.Binary;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Регрессия: раньше временем записи UserAssist служил LastWrite ключа Count
/// целиком. Любое действие в проводнике обновляет этот ключ, и ВСЕ записи
/// UserAssist получали время сканирования — старые следы всплывали в таймлайне
/// как «свежие запуски» сразу после каждого полного сканирования.
/// Теперь время и счётчик читаются из данных самого значения.
/// </summary>
public class UserAssistEntryParserTests
{
    private static byte[] Entry(int runCount, long fileTime)
    {
        var bytes = new byte[72];
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4), runCount);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(60), fileTime);
        return bytes;
    }

    [Fact]
    public void Reads_run_count_and_last_run_time_from_value_data()
    {
        var when = new DateTimeOffset(2026, 8, 1, 10, 0, 0, TimeSpan.Zero);

        var (runCount, lastRunUtc) = UserArtifactCollector.ParseUserAssistEntry(
            Entry(7, when.ToFileTime()));

        Assert.Equal(7, runCount);
        Assert.Equal(when, lastRunUtc);
    }

    [Fact]
    public void Zero_filetime_means_no_recorded_launch_not_scan_time()
    {
        var (runCount, lastRunUtc) = UserArtifactCollector.ParseUserAssistEntry(Entry(0, 0));

        Assert.Equal(0, runCount);
        Assert.Null(lastRunUtc);
    }

    [Fact]
    public void Garbage_filetime_before_2000_is_rejected()
    {
        var (_, lastRunUtc) = UserArtifactCollector.ParseUserAssistEntry(Entry(3, 12345));

        Assert.Null(lastRunUtc);
    }

    [Fact]
    public void Future_filetime_is_rejected()
    {
        var future = DateTimeOffset.UtcNow.AddYears(5).ToFileTime();

        var (_, lastRunUtc) = UserArtifactCollector.ParseUserAssistEntry(Entry(3, future));

        Assert.Null(lastRunUtc);
    }

    [Fact]
    public void Short_xp_style_structure_is_tolerated_without_data()
    {
        var (runCount, lastRunUtc) = UserArtifactCollector.ParseUserAssistEntry(new byte[16]);

        Assert.Null(runCount);
        Assert.Null(lastRunUtc);
    }

    [Fact]
    public void Negative_filetime_is_rejected_without_exception()
    {
        var (_, lastRunUtc) = UserArtifactCollector.ParseUserAssistEntry(Entry(1, -5));

        Assert.Null(lastRunUtc);
    }
}
