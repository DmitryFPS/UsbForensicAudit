using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;

namespace UsbForensicAudit;

/// <summary>Только точечное удаление PnP-экземпляра штатной командой Windows.</summary>
public sealed class WindowsDeviceRemovalPlatform : IDeviceRemovalPlatform
{
    private const string EnumRoot = @"SYSTEM\CurrentControlSet\Enum\";
    private readonly string _backupRoot;
    private readonly Func<string, bool> _present;
    private readonly Func<string, bool> _exists;
    private readonly Func<string, string[], CancellationToken, Task<DeviceRemovalCommandResult>> _run;
    private readonly Action _ensureSupported;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public WindowsDeviceRemovalPlatform(string dataDirectory)
        : this(dataDirectory, NativeIsPresent, NativeInstanceExists, RunAsync, EnsureNativeRemovalSupported)
    {
    }

    internal WindowsDeviceRemovalPlatform(string dataDirectory, Func<string, bool> present, Func<string, bool> exists,
        Func<string, string[], CancellationToken, Task<DeviceRemovalCommandResult>> run, Action ensureSupported)
    {
        _backupRoot = Path.GetFullPath(Path.Combine(dataDirectory, "device-removal"));
        _present = present;
        _exists = exists;
        _run = run;
        _ensureSupported = ensureSupported;
    }

    public string ComputerName => Environment.MachineName;

    public IReadOnlyList<DeviceRemovalNode> ReadInventory()
    {
        var nodes = new List<DeviceRemovalNode>();
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        // Неполный список не подтверждает отсутствие подключённых компонентов.
        foreach (var bus in new[] { "USB", "USBSTOR", "SWD", "SCSI", "STORAGE", "HID", "USBPRINT" })
        {
            using var busKey = machine.OpenSubKey(EnumRoot + bus);
            if (busKey is null)
            {
                continue;
            }

            foreach (var model in busKey.GetSubKeyNames())
            {
                using var modelKey = busKey.OpenSubKey(model)
                    ?? throw new IOException("Список устройств изменился во время чтения. Повторите проверку.");
                foreach (var instance in modelKey.GetSubKeyNames())
                {
                    using var key = modelKey.OpenSubKey(instance)
                        ?? throw new IOException("Экземпляр исчез во время чтения. Повторите проверку.");
                    var id = $@"{bus}\{model}\{instance}";
                    bool? present;
                    try { present = IsPresent(id); }
                    catch (InvalidOperationException) { present = null; }
                    var name = Text(key, "FriendlyName");
                    if (name.Length == 0)
                    {
                        name = Text(key, "DeviceDesc");
                    }

                    var auditId = bus.Equals("SWD", StringComparison.OrdinalIgnoreCase)
                                  && model.Equals("WPDBUSENUM", StringComparison.OrdinalIgnoreCase)
                        ? UsbRegistryForensicHelpers.BuildWpdInstanceId(UsbRegistryForensicHelpers.ParseWpdIdentity(instance))
                        : id;
                    nodes.Add(new(id, UserDisplayText.DeviceDisplayName(name, "", "", id), present,
                        Text(key, "ContainerID"), Text(key, "Service"), Text(key, "ClassGUID"),
                        Text(key, "ParentIdPrefix"), Text(key, "HardwareID"), auditId));
                }
            }
        }
        return nodes;
    }

    public bool IsPresent(string instanceId) => _present(instanceId);
    private static bool NativeIsPresent(string instanceId) => PresenceFromResult(CM_Locate_DevNodeW(out _, instanceId, 0));

    public static bool PresenceFromResult(uint result) => result switch
    {
        0 => true,
        0x0D => false,
        _ => throw new InvalidOperationException($"Не удалось проверить подключение (CONFIGRET 0x{result:X}).")
    };

    public bool InstanceExists(string instanceId)
    {
        ValidateId(instanceId);
        return _exists(instanceId);
    }

    private static bool NativeInstanceExists(string instanceId)
    {
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = machine.OpenSubKey(EnumRoot + instanceId);
        return key is not null;
    }

    public void EnsureRemovalSupported() => _ensureSupported();

    private static void EnsureNativeRemovalSupported()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041))
        {
            throw new InvalidOperationException("Удаление экземпляров поддерживается начиная с Windows 10 версии 2004.");
        }

        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw new UnauthorizedAccessException("Для удаления запустите приложение от имени администратора.");
        }
    }

    public async Task<string> BackupAsync(DeviceRemovalPlan plan, CancellationToken cancellationToken)
    {
        var directory = Path.Combine(_backupRoot, $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var exports = new List<object>();
        foreach (var item in plan.Items.Where(x => x.CanRemove))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidateId(item.InstanceId);
            if (!InstanceExists(item.InstanceId))
            {
                if (IsPresent(item.InstanceId))
                {
                    throw new IOException("Состояние устройства изменилось при резервном копировании.");
                }

                exports.Add(new { item.InstanceId, AlreadyAbsent = true });
                continue;
            }
            var file = Path.Combine(directory, $"device-{exports.Count + 1:D4}.reg");
            var command = await _run("reg.exe", ["export", @"HKLM\" + EnumRoot + item.InstanceId, file, "/y"], cancellationToken);
            if (command.ExitCode != 0 || !File.Exists(file) || new FileInfo(file).Length == 0)
            {
                throw new IOException($"Не удалось сохранить копию {item.InstanceId}. Удаление не начато. {command.Output}");
            }

            var content = await File.ReadAllTextAsync(file, cancellationToken);
            if (!content.StartsWith("Windows Registry Editor Version 5.00", StringComparison.Ordinal)
                || !content.Contains("[HKEY_LOCAL_MACHINE\\" + EnumRoot + item.InstanceId + "]", StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("Резервная копия не содержит выбранную запись. Удаление не начато.");
            }

            using var stream = File.OpenRead(file);
            exports.Add(new { item.InstanceId, File = Path.GetFileName(file), Sha256 = Convert.ToHexString(SHA256.HashData(stream)) });
        }
        await File.WriteAllTextAsync(Path.Combine(directory, "manifest.json"),
            JsonSerializer.Serialize(new
            {
                Plan = plan,
                Exports = exports,
                Note = "Копии .reg сохраняют выбранные записи реестра, но не являются полным откатом PnP. Повторное подключение устройства запускает обычную установку Windows."
            }, JsonOptions), cancellationToken);
        return directory;
    }

    public Task<DeviceRemovalCommandResult> RemoveAsync(string instanceId)
    {
        EnsureRemovalSupported();
        ValidateId(instanceId);
        if (IsPresent(instanceId))
        {
            throw new InvalidOperationException("Устройство снова подключено. Удаление отменено.");
        }

        return _run("pnputil.exe", ["/remove-device", instanceId], CancellationToken.None);
    }

    public Task SaveResultAsync(string backupDirectory, DeviceRemovalResult result) =>
        File.WriteAllTextAsync(Path.Combine(backupDirectory, "result.json"), JsonSerializer.Serialize(result, JsonOptions));

    private static async Task<DeviceRemovalCommandResult> RunAsync(string executable, string[] arguments, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, executable))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new IOException("Не удалось запустить штатную команду Windows.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(45));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }

            await process.WaitForExitAsync(CancellationToken.None);
            await Task.WhenAll(output, error);
            throw new IOException("Команда Windows не завершилась вовремя или отменена. Результат не подтверждён; выполните повторный поиск.");
        }
        return new(process.ExitCode, (await output + Environment.NewLine + await error).Trim());
    }

    private static void ValidateId(string id)
    {
        if (!DeviceRemovalPolicy.IsInstanceId(id))
        {
            throw new ArgumentException("Недопустимый ID экземпляра.", nameof(id));
        }
    }

    private static string Text(RegistryKey key, string name) => key.GetValue(name) switch
    {
        string text => text,
        string[] values => string.Join("|", values),
        _ => ""
    };

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint CM_Locate_DevNodeW(out uint devInst, string deviceId, uint flags);
}
