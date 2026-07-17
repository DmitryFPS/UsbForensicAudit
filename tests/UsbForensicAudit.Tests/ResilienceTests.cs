using System.IO;
using Microsoft.Data.Sqlite;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class DevicePathNormalizerTests
{
    [Theory]
    [InlineData(@"USB\\VID_0951&PID_1666\\SERIAL", @"USB\VID_0951&PID_1666\SERIAL")]
    [InlineData(@"USB\\\\VID_0951&PID_1666", @"USB\VID_0951&PID_1666")]
    [InlineData(@"{usb\\vid_0951&pid_1666}", @"usb\vid_0951&pid_1666")]
    public void NormalizeDeviceId_collapses_all_repeated_separators(string input, string expected)
    {
        Assert.Equal(expected, DevicePathNormalizer.NormalizeDeviceId(input));
    }

    [Fact]
    public void CanonicalDeviceId_normalizes_hashes_and_case()
    {
        Assert.Equal(
            @"USB\VID_0951&PID_1666\SERIAL",
            DevicePathNormalizer.CanonicalDeviceId(@"usb#vid_0951&pid_1666##serial", replaceHashes: true));
    }
}

public sealed class StorageConcurrencyTests
{
    [Fact]
    public async Task Parallel_storage_instances_preserve_sqlite_and_jsonl_chain()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-concurrent-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            const int count = 8;
            await Task.WhenAll(Enumerable.Range(0, count).Select(index => Task.Run(() =>
            {
                var storage = new AuditStorage(directory);
                storage.Save(CreateResult($"session-{index}"));
            })));

            var verifier = new AuditStorage(directory);
            for (var index = 0; index < count; index++)
            {
                Assert.NotNull(verifier.Load($"session-{index}"));
            }

            var previousHash = "";
            var records = 0;
            foreach (var line in File.ReadLines(verifier.JsonlPath))
            {
                using var document = System.Text.Json.JsonDocument.Parse(line);
                Assert.Equal(previousHash, document.RootElement.GetProperty("previousHash").GetString());
                previousHash = document.RootElement.GetProperty("recordHash").GetString() ?? "";
                Assert.NotEmpty(previousHash);
                records++;
            }

            Assert.Equal(count * 3, records);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public void Corrupt_jsonl_tail_is_rejected_instead_of_silently_breaking_chain()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-corrupt-chain-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var storage = new AuditStorage(directory);
            storage.Save(CreateResult("first"));
            File.AppendAllText(storage.JsonlPath, "not-json" + Environment.NewLine);

            var exception = Assert.Throws<InvalidDataException>(() => storage.Save(CreateResult("second")));
            Assert.Contains("hash-chain", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public void Corrupt_jsonl_middle_is_rejected_during_session_completion_recovery()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-corrupt-middle-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var storage = new AuditStorage(directory);
            var result = CreateResult("recover");
            storage.Save(result);

            var lines = File.ReadAllLines(storage.JsonlPath).ToList();
            lines.Insert(1, "not-json");
            File.WriteAllLines(storage.JsonlPath, lines);

            using (var connection = new SqliteConnection($"Data Source={storage.DatabasePath}"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = "UPDATE audit_sessions SET jsonl_appended=0 WHERE session_id='recover';";
                Assert.Equal(1, command.ExecuteNonQuery());
            }

            var exception = Assert.Throws<InvalidDataException>(() => storage.Save(result));
            Assert.Contains("повреждённую", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    private static AuditResult CreateResult(string sessionId)
    {
        var now = DateTimeOffset.UtcNow;
        var result = new AuditResult
        {
            SessionId = sessionId,
            StartedAtUtc = now,
            FinishedAtUtc = now
        };
        result.Devices.Add(new UsbDeviceRecord
        {
            DeviceInstanceId = $@"USB\VID_0951&PID_1666\{sessionId}",
            Source = "test"
        });
        return result;
    }
}

public sealed class StaTaskRunnerTests
{
    [Fact]
    public async Task RunAsync_returns_result_from_sta_thread()
    {
        var result = await StaTaskRunner.RunAsync(
            () => (Thread.CurrentThread.GetApartmentState(), 42),
            TimeSpan.FromSeconds(2));

        Assert.Equal(ApartmentState.STA, result.Item1);
        Assert.Equal(42, result.Item2);
    }

    [Fact]
    public async Task RunAsync_enforces_timeout()
    {
        await Assert.ThrowsAsync<TimeoutException>(() =>
            StaTaskRunner.RunAsync(
                () =>
                {
                    Thread.Sleep(250);
                    return true;
                },
                TimeSpan.FromMilliseconds(25)));
    }
}
