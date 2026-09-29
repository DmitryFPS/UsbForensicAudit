using System.IO;
using System.Text;
using System.Text.Json;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceRemovalBackupTests : IDisposable
{
    [Fact]
    public async Task Native_backup_rejects_active_enum_and_only_exports_inactive_control_set()
    {
        using var machine = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);
        using var select = machine.OpenSubKey(@"SYSTEM\Select");
        var current = Assert.IsType<int>(select!.GetValue("Current"));
        var active = $@"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet{current:D3}\Enum\{Id}";
        var inactive = $@"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet{(current == 1 ? 2 : 1):D3}\Enum\{Id}";
        var calls = new List<string>();
        var platform = new WindowsDeviceRemovalPlatform(_directory, _ => false, _ => false,
            async (_, args, token) =>
            {
                calls.Add(args[1]);
                await File.WriteAllTextAsync(args[2], "Windows Registry Editor Version 5.00\r\n[" + args[1] + "]\r\n", Encoding.Unicode, token);
                return new(0, "");
            }, () => { }, _ => "original");
        var trace = new DeviceRegistryTrace(active, "original", [Id]);
        var item = new DeviceRemovalItem(active, "USB", true, "", null, [Id], trace);
        var plan = new DeviceRemovalPlan("TEST", "test", DateTimeOffset.UtcNow, [item]);
        Assert.True(platform.IsActiveEnumPath(active));
        Assert.False(platform.IsActiveEnumPath(inactive));
        await Assert.ThrowsAsync<IOException>(() => platform.BackupAsync(plan, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => platform.RemoveTraceAsync(trace));
        Assert.Empty(calls);
        var backup = await platform.BackupAsync(plan with { Items = [item with { InstanceId = inactive, Trace = trace with { RegistryPath = inactive } }] }, CancellationToken.None);
        Assert.Equal(inactive, Assert.Single(calls));
        Assert.True(File.Exists(Path.Combine(backup, "manifest.json")));
        Assert.Throws<ArgumentOutOfRangeException>(() => WindowsDeviceRemovalPlatform.IsActiveEnumPath(inactive, 0));
    }

    [Fact]
    public async Task Historical_trace_backup_exports_exact_key_and_checks_snapshot_after_export()
    {
        const string path = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices\USB#VID_1234&PID_5678#SERIAL";
        var fingerprint = "original";
        var changeDuringExport = false;
        var calls = new List<string[]>();
        var platform = new WindowsDeviceRemovalPlatform(_directory, _ => false, _ => false,
            async (exe, args, token) =>
            {
                Assert.Equal("reg.exe", exe);
                calls.Add(args);
                await File.WriteAllTextAsync(args[2], "Windows Registry Editor Version 5.00\r\n[" + path + "]\r\n", Encoding.Unicode, token);
                if (changeDuringExport)
                {
                    fingerprint = "modified";
                }

                return new(0, "");
            }, () => { }, _ => fingerprint);
        var trace = new DeviceRegistryTrace(path, "original", [Id]);
        var plan = new DeviceRemovalPlan("TEST", "test", DateTimeOffset.UtcNow,
            [new(path, "Historical device", true, "", null, [Id], trace)]);
        var directory = await platform.BackupAsync(plan, CancellationToken.None);
        Assert.Equal(["export", path, Path.Combine(directory, "device-0001.reg"), "/y"], Assert.Single(calls));
        changeDuringExport = true;
        await Assert.ThrowsAsync<IOException>(() => platform.BackupAsync(plan, CancellationToken.None));
        // Следующая попытка обнаружит изменение до запуска reg.exe.
        await Assert.ThrowsAsync<IOException>(() => platform.BackupAsync(plan, CancellationToken.None));
        Assert.Equal(2, calls.Count);
    }

    [Fact]
    public async Task Already_absent_trace_is_documented_and_invalid_trace_path_cannot_be_exported()
    {
        const string path = @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\usbflags\123456780100";
        var platform = new WindowsDeviceRemovalPlatform(_directory, _ => false, _ => false,
            (_, _, _) => throw new Exception("No command expected"), () => { }, _ => null);
        var trace = new DeviceRegistryTrace(path, "original", [], "1234", "5678");
        var item = new DeviceRemovalItem(path, "Model cache", true, "", null, [], trace);
        var plan = new DeviceRemovalPlan("TEST", "test", DateTimeOffset.UtcNow, [item]);
        var directory = await platform.BackupAsync(plan, CancellationToken.None);
        Assert.Contains("AlreadyAbsent", await File.ReadAllTextAsync(Path.Combine(directory, "manifest.json")));
        var invalid = item with { Trace = trace with { RegistryPath = @"HKLM\SYSTEM" } };
        await Assert.ThrowsAsync<ArgumentException>(() => platform.BackupAsync(plan with { Items = [invalid] }, CancellationToken.None));
        Assert.Throws<ArgumentException>(() => platform.ReadTraceFingerprint(@"HKLM\SYSTEM"));
    }

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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Privileged_backup_uses_exact_key_hive_and_rejects_invalid_output(bool invalid)
    {
        var called = false;
        var platform = new WindowsDeviceRemovalPlatform(_directory, _ => false, _ => true,
            (_, _, _) => throw new Exception("reg.exe cannot read protected Properties"), () => { },
            saveRegistryKey: (path, file) =>
            {
                Assert.Equal(@"HKLM\SYSTEM\CurrentControlSet\Enum\" + Id, path);
                Assert.EndsWith(".hiv", file);
                called = true;
                File.WriteAllBytes(file, invalid ? [0, 0, 0, 0] : "regf"u8.ToArray());
            });
        if (invalid)
        {
            await Assert.ThrowsAsync<IOException>(() => platform.BackupAsync(Plan(), CancellationToken.None));
        }
        else
        {
            var backup = await platform.BackupAsync(Plan(), CancellationToken.None);
            Assert.Contains("device-0001.hiv", await File.ReadAllTextAsync(Path.Combine(backup, "manifest.json")));
        }
        Assert.True(called);
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
