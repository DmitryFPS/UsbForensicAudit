using System.IO;
using System.Text;
using System.Text.Json;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceRemovalBackupTests : IDisposable
{
    private const string Id = @"USB\VID_1234&PID_5678\SERIAL";
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "UsbForensicAudit-backup-test-" + Guid.NewGuid().ToString("N"));
    private static DeviceRemovalPlan Plan() => new("TEST", "test", DateTimeOffset.UtcNow,
        [new(Id, "Test", true, "", new(Id, "Test", false, Service: "USBSTOR"), [Id])]);

    [Fact]
    public async Task Backup_exports_exact_instances_and_records_hashes_and_results()
    {
        var calls = new List<string[]>();
        var platform = Adapter(async (exe, args, token) =>
        {
            Assert.Equal("reg.exe", exe);
            calls.Add(args);
            await File.WriteAllTextAsync(args[2],
                "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\" + Id + "]\r\n",
                Encoding.Unicode, token);
            return new(0, "");
        });
        var backup = await platform.BackupAsync(Plan(), CancellationToken.None);
        Assert.Equal(["export", @"HKLM\SYSTEM\CurrentControlSet\Enum\" + Id, Path.Combine(backup, "device-0001.reg"), "/y"],
            Assert.Single(calls));
        using var manifest = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(backup, "manifest.json")));
        Assert.Equal(64, manifest.RootElement.GetProperty("Exports")[0].GetProperty("Sha256").GetString()!.Length);
        var result = new DeviceRemovalResult(backup, [new(Id, "Test", "Removed", "Done")]);
        await platform.SaveResultAsync(backup, result);
        Assert.Contains("Removed", await File.ReadAllTextAsync(Path.Combine(backup, "result.json")));
        Assert.NotEmpty(platform.ComputerName);
    }

    [Theory]
    [InlineData(5, false)]
    [InlineData(0, false)]
    [InlineData(0, true)]
    public async Task Export_failure_missing_file_and_invalid_export_abort_backup(int code, bool writeInvalid)
    {
        var platform = Adapter(async (_, args, token) =>
        {
            if (writeInvalid)
            {
                await File.WriteAllTextAsync(args[2], "incorrect export", token);
            }

            return new(code, "Error");
        });
        await Assert.ThrowsAsync<IOException>(() => platform.BackupAsync(Plan(), CancellationToken.None));
    }

    [Fact]
    public async Task Already_absent_key_is_explicitly_recorded_without_an_export_command()
    {
        var platform = Adapter((_, _, _) => throw new InvalidOperationException("Unexpected command"), exists: false);
        var backup = await platform.BackupAsync(Plan(), CancellationToken.None);
        Assert.Contains("\"AlreadyAbsent\": true", await File.ReadAllTextAsync(Path.Combine(backup, "manifest.json")));
    }

    [Fact]
    public async Task Disappeared_key_with_present_device_aborts_backup()
    {
        var platform = Adapter((_, _, _) => throw new InvalidOperationException("Unexpected command"), exists: false, present: true);
        await Assert.ThrowsAsync<IOException>(() => platform.BackupAsync(Plan(), CancellationToken.None));
    }

    [Fact]
    public async Task Removal_uses_only_one_exact_instance_argument()
    {
        var checkedPermissions = false;
        var platform = new WindowsDeviceRemovalPlatform(_directory, _ => false, _ => true, (exe, args, _) =>
        {
            Assert.True(checkedPermissions);
            Assert.Equal("pnputil.exe", exe);
            Assert.Equal(["/remove-device", Id], args);
            return Task.FromResult(new DeviceRemovalCommandResult(0, "Done"));
        }, () => checkedPermissions = true);
        Assert.Equal(0, (await platform.RemoveAsync(Id)).ExitCode);
    }

    [Fact]
    public async Task Connected_or_invalid_instance_never_invokes_the_command()
    {
        var platform = Adapter((_, _, _) => throw new Exception("Unexpected command"), present: true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => platform.RemoveAsync(Id));
        await Assert.ThrowsAsync<ArgumentException>(() => platform.RemoveAsync(@"USB\*"));
        Assert.Throws<ArgumentException>(() => platform.InstanceExists(@"USB\*"));
    }

    private WindowsDeviceRemovalPlatform Adapter(
        Func<string, string[], CancellationToken, Task<DeviceRemovalCommandResult>> command,
        bool exists = true, bool present = false) =>
        new(_directory, _ => present, _ => exists, command, () => { });

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
