using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace UsbForensicAudit;

/// <summary>
/// Офлайн-аудит чужой системы: смонтированный образ диска или скопированный
/// каталог Windows. Кусты SYSTEM/SOFTWARE/NTUSER.DAT копируются во временный
/// каталог и загружаются через reg load — исследуемые файлы не изменяются.
///
/// Это не полный конвейер живого сканирования: WMI, журналы событий и
/// работающие процессы чужой машины недоступны по определению. Всё, что
/// прочитать нельзя, честно попадает в предупреждения, а не замалчивается.
/// </summary>
public sealed class OfflineWindowsAuditor : IOfflineWindowsAuditor
{
    private static readonly Regex VidPidRegex = new(
        @"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public AuditResult Audit(string root, CancellationToken cancellationToken = default)
    {
        var windowsDirectory = FindWindowsDirectory(root)
            ?? throw new DirectoryNotFoundException(
                $"Каталог Windows не найден в «{root}». Укажите корень диска с папкой Windows " +
                "или сам каталог Windows (в нём должен быть System32\\config\\SYSTEM).");

        var result = new AuditResult
        {
            SessionId = $"offline-{Guid.NewGuid():N}",
            ComputerName = "offline",
            UserName = Environment.UserName,
            WindowsVersion = "offline-источник",
            IsAdministrator = true
        };
        result.SourceWarnings.Add(
            $"Офлайн-анализ: {windowsDirectory}. Журналы событий, WMI и работающие процессы " +
            "чужой машины недоступны — отчёт построен по кустам реестра и файловым " +
            "артефактам профилей (LNK, Jump Lists).");

        var warnings = result.SourceWarnings;
        using (var system = MountedHive.Load(
                   Path.Combine(windowsDirectory, "System32", "config", "SYSTEM"), warnings))
        {
            if (system is not null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CollectFromSystemHive(system, result, warnings);
            }
        }

        using (var software = MountedHive.Load(
                   Path.Combine(windowsDirectory, "System32", "config", "SOFTWARE"), warnings))
        {
            if (software is not null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CollectFromSoftwareHive(software, result, warnings);
            }
        }

        CollectFromUserHives(windowsDirectory, result, warnings, cancellationToken);
        OfflineUserFileArtifactCollector.Collect(
            ResolveUsersDirectory(windowsDirectory), result, warnings, cancellationToken);

        foreach (var device in result.Devices)
        {
            device.SessionId = result.SessionId;
        }

        foreach (var record in result.Evidence)
        {
            record.SessionId = result.SessionId;
        }

        result.FinishedAtUtc = DateTimeOffset.UtcNow;
        return result;
    }

    /// <summary>
    /// Принимает и корень диска, и сам каталог Windows: следователь передаёт то,
    /// что видит, а угадывать за него глубину пути инструмент обязан сам.
    /// </summary>
    internal static string? FindWindowsDirectory(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            return null;
        }

        var full = Path.GetFullPath(root.Trim());
        if (HiveExists(full))
        {
            return full;
        }

        var nested = Path.Combine(full, "Windows");
        return HiveExists(nested) ? nested : null;

        static bool HiveExists(string candidate) =>
            File.Exists(Path.Combine(candidate, "System32", "config", "SYSTEM"));
    }

    private static void CollectFromSystemHive(MountedHive hive, AuditResult result, List<string> warnings)
    {
        var computerName = hive.ReadString(
            @"ControlSet001\Control\ComputerName\ComputerName", "ComputerName");
        if (!string.IsNullOrWhiteSpace(computerName))
        {
            result.ComputerName = $"offline:{computerName}";
        }

        foreach (var controlSet in hive.SubKeyNames("")
                     .Where(x => x.StartsWith("ControlSet", StringComparison.OrdinalIgnoreCase)))
        {
            CollectUsbStor(hive, controlSet, result, warnings);
            CollectUsbEnum(hive, controlSet, result, warnings);
        }

        CollectMountedDevices(hive, result, warnings);
    }

    private static void CollectUsbStor(
        MountedHive hive, string controlSet, AuditResult result, List<string> warnings)
    {
        var basePath = $@"{controlSet}\Enum\USBSTOR";
        foreach (var model in hive.SubKeyNames(basePath))
        {
            foreach (var serial in hive.SubKeyNames($@"{basePath}\{model}"))
            {
                using var instance = hive.OpenKey($@"{basePath}\{model}\{serial}");
                if (instance is null)
                {
                    continue;
                }

                var instanceId = $@"USBSTOR\{model}\{serial}";
                if (result.Devices.Any(x =>
                        x.DeviceInstanceId.Equals(instanceId, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                var parts = ParseUsbStorModel(model);
                result.Devices.Add(new UsbDeviceRecord
                {
                    DeviceInstanceId = instanceId,
                    Source = $"Offline USBSTOR ({controlSet})",
                    DeviceType = "USB Mass Storage",
                    DeviceKind = "Storage",
                    Transport = "USB",
                    TransportConfidence = "High",
                    TransportProvenance = [$@"Offline SYSTEM\{basePath}\{model}\{serial}"],
                    Classification = "Removable Storage",
                    ClassificationConfidence = "Medium",
                    ClassificationProvenance = ["Offline USBSTOR: тип определён по ветке реестра"],
                    Serial = TrimSerialSuffix(serial),
                    FriendlyName = hive.ReadString(instance, "FriendlyName"),
                    Manufacturer = parts.Vendor,
                    Product = parts.Product,
                    Revision = parts.Revision,
                    Service = hive.ReadString(instance, "Service"),
                    ContainerId = hive.ReadString(instance, "ContainerID"),
                    RegistryLastWriteUtc = RegistryKeyTimestamps.GetLastWriteUtc(instance)
                });
            }
        }
    }

    private static void CollectUsbEnum(
        MountedHive hive, string controlSet, AuditResult result, List<string> warnings)
    {
        var basePath = $@"{controlSet}\Enum\USB";
        foreach (var hardwareId in hive.SubKeyNames(basePath))
        {
            var match = VidPidRegex.Match(hardwareId);
            foreach (var serial in hive.SubKeyNames($@"{basePath}\{hardwareId}"))
            {
                using var instance = hive.OpenKey($@"{basePath}\{hardwareId}\{serial}");
                if (instance is null)
                {
                    continue;
                }

                var instanceId = $@"USB\{hardwareId}\{serial}";
                if (result.Devices.Any(x =>
                        x.DeviceInstanceId.Equals(instanceId, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                result.Devices.Add(new UsbDeviceRecord
                {
                    DeviceInstanceId = instanceId,
                    Source = $"Offline USB ({controlSet})",
                    DeviceType = "USB Device",
                    Transport = "USB",
                    TransportConfidence = "High",
                    TransportProvenance = [$@"Offline SYSTEM\{basePath}\{hardwareId}\{serial}"],
                    Vid = match.Success ? match.Groups[1].Value.ToUpperInvariant() : "",
                    Pid = match.Success ? match.Groups[2].Value.ToUpperInvariant() : "",
                    Serial = TrimSerialSuffix(serial),
                    FriendlyName = hive.ReadString(instance, "FriendlyName"),
                    Manufacturer = hive.ReadString(instance, "Mfg"),
                    Service = hive.ReadString(instance, "Service"),
                    ContainerId = hive.ReadString(instance, "ContainerID"),
                    LocationInformation = hive.ReadString(instance, "LocationInformation"),
                    RegistryLastWriteUtc = RegistryKeyTimestamps.GetLastWriteUtc(instance)
                });
            }
        }
    }

    private static void CollectMountedDevices(MountedHive hive, AuditResult result, List<string> warnings)
    {
        using var key = hive.OpenKey("MountedDevices");
        if (key is null)
        {
            warnings.Add("Офлайн SYSTEM: ветка MountedDevices не найдена.");
            return;
        }

        foreach (var valueName in key.GetValueNames())
        {
            if (key.GetValue(valueName) is not byte[] raw)
            {
                continue;
            }

            var text = System.Text.Encoding.Unicode.GetString(raw);
            if (!text.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            result.Evidence.Add(new EvidenceRecord
            {
                Source = "Offline MountedDevices",
                EvidenceCategory = "VolumeMapping",
                Summary = $"Том {valueName} сопоставлен USB-накопителю",
                RawText = TextSanitizer.NormalizeDisplay(text, 500),
                DeviceHint = TextSanitizer.NormalizeDisplay(text, 200),
                Provenance = $@"Offline SYSTEM\MountedDevices\{valueName}",
                EvidenceStrength = "Direct",
                Confidence = "Medium",
                SourceFile = hive.SourcePath,
                SourceSha256 = hive.SourceSha256
            });
        }
    }

    private static void CollectFromSoftwareHive(MountedHive hive, AuditResult result, List<string> warnings)
    {
        var installDate = hive.ReadDword(@"Microsoft\Windows NT\CurrentVersion", "InstallDate");
        if (installDate > 0)
        {
            result.OsInstalledAtUtc = DateTimeOffset.FromUnixTimeSeconds(installDate);
        }

        var productName = hive.ReadString(@"Microsoft\Windows NT\CurrentVersion", "ProductName");
        if (!string.IsNullOrWhiteSpace(productName))
        {
            result.WindowsVersion = $"offline: {productName}";
        }

        using var wpd = hive.OpenKey(@"Microsoft\Windows Portable Devices\Devices");
        if (wpd is null)
        {
            return;
        }

        foreach (var deviceKeyName in wpd.GetSubKeyNames())
        {
            using var deviceKey = wpd.OpenSubKey(deviceKeyName);
            var friendly = deviceKey?.GetValue("FriendlyName") as string ?? "";
            result.Evidence.Add(new EvidenceRecord
            {
                Source = "Offline Windows Portable Devices",
                EvidenceCategory = "PortableDevice",
                Summary = string.IsNullOrWhiteSpace(friendly)
                    ? "Переносное устройство подключалось к системе"
                    : $"Переносное устройство «{friendly}» подключалось к системе",
                RawText = TextSanitizer.NormalizeDisplay(deviceKeyName, 500),
                DeviceHint = friendly,
                Provenance = $@"Offline SOFTWARE\Microsoft\Windows Portable Devices\Devices\{deviceKeyName}",
                EvidenceStrength = "Direct",
                Confidence = "Medium",
                SourceFile = hive.SourcePath,
                SourceSha256 = hive.SourceSha256,
                RegistryLastWriteUtc = deviceKey is null ? null : RegistryKeyTimestamps.GetLastWriteUtc(deviceKey)
            });
        }
    }

    /// <summary>Каталог Users рядом с каталогом Windows исследуемого образа.</summary>
    internal static string ResolveUsersDirectory(string windowsDirectory) =>
        Path.Combine(
            Path.GetDirectoryName(windowsDirectory.TrimEnd(Path.DirectorySeparatorChar)) ?? windowsDirectory,
            "Users");

    private static void CollectFromUserHives(
        string windowsDirectory, AuditResult result, List<string> warnings, CancellationToken cancellationToken)
    {
        var usersDirectory = ResolveUsersDirectory(windowsDirectory);
        if (!Directory.Exists(usersDirectory))
        {
            warnings.Add(
                "Офлайн-анализ: каталог Users рядом с Windows не найден — история подключений " +
                "по пользователям (MountPoints2) недоступна.");
            return;
        }

        foreach (var profile in Directory.EnumerateDirectories(usersDirectory).Take(256))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ntUser = Path.Combine(profile, "NTUSER.DAT");
            if (!File.Exists(ntUser))
            {
                continue;
            }

            var userName = Path.GetFileName(profile);
            using var hive = MountedHive.Load(ntUser, warnings);
            if (hive is null)
            {
                continue;
            }

            using var mountPoints = hive.OpenKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2");
            if (mountPoints is null)
            {
                continue;
            }

            foreach (var name in mountPoints.GetSubKeyNames()
                         .Where(x => x.StartsWith("{", StringComparison.Ordinal)))
            {
                using var pointKey = mountPoints.OpenSubKey(name);
                result.Evidence.Add(new EvidenceRecord
                {
                    Source = "Offline MountPoints2",
                    EvidenceCategory = "UserVolumeAccess",
                    Summary = $"Пользователь «{userName}» обращался к тому {name}",
                    RawText = name,
                    DeviceHint = name,
                    ResolvedUserName = userName,
                    Provenance = $@"Offline NTUSER.DAT ({userName})\...\MountPoints2\{name}",
                    EvidenceStrength = "Indirect",
                    Confidence = "Medium",
                    SourceFile = ntUser,
                    SourceSha256 = hive.SourceSha256,
                    RegistryLastWriteUtc = pointKey is null ? null : RegistryKeyTimestamps.GetLastWriteUtc(pointKey)
                });
            }
        }
    }

    /// <summary>
    /// Имя модели USBSTOR: Disk&amp;Ven_Kingston&amp;Prod_DataTraveler&amp;Rev_PMAP.
    /// </summary>
    internal static (string Vendor, string Product, string Revision) ParseUsbStorModel(string model)
    {
        string vendor = "", product = "", revision = "";
        foreach (var part in model.Split('&'))
        {
            if (part.StartsWith("Ven_", StringComparison.OrdinalIgnoreCase))
            {
                vendor = part[4..].Replace('_', ' ').Trim();
            }
            else if (part.StartsWith("Prod_", StringComparison.OrdinalIgnoreCase))
            {
                product = part[5..].Replace('_', ' ').Trim();
            }
            else if (part.StartsWith("Rev_", StringComparison.OrdinalIgnoreCase))
            {
                revision = part[4..].Trim();
            }
        }

        return (vendor, product, revision);
    }

    /// <summary>
    /// Серийники в реестре получают суффикс экземпляра «&amp;0»/«&amp;1» — это счётчик
    /// PnP, а не часть заводского номера, и в отчёте он только мешает сравнению.
    /// </summary>
    internal static string TrimSerialSuffix(string serial)
    {
        var index = serial.LastIndexOf('&');
        return index > 0 && index >= serial.Length - 3 ? serial[..index] : serial;
    }

    /// <summary>
    /// Куст реестра, загруженный из копии файла под временным именем HKLM.
    /// Копирование обязательно: reg load пишет в hive-файл, а исследуемый
    /// источник должен остаться нетронутым.
    /// </summary>
    private sealed class MountedHive : IDisposable
    {
        private readonly string _mountName;
        private readonly string _tempDirectory;
        private RegistryKey? _rootKey;

        public string SourcePath { get; }
        public string SourceSha256 { get; }

        private MountedHive(string mountName, string tempDirectory, string sourcePath, string sourceSha256)
        {
            _mountName = mountName;
            _tempDirectory = tempDirectory;
            SourcePath = sourcePath;
            SourceSha256 = sourceSha256;
        }

        public static MountedHive? Load(string hivePath, List<string> warnings)
        {
            if (!File.Exists(hivePath))
            {
                warnings.Add($"Офлайн-куст не найден: {hivePath}");
                return null;
            }

            var tempDirectory = Path.Combine(
                Path.GetTempPath(), "UsbForensicAudit", "offline", Guid.NewGuid().ToString("N"));
            var mountName = $"UFA_OFFLINE_{Guid.NewGuid():N}";
            try
            {
                Directory.CreateDirectory(tempDirectory);
                var copy = Path.Combine(tempDirectory, Path.GetFileName(hivePath));
                var outcome = LockedFileCopier.Copy(hivePath, copy);
                if (!outcome.Success)
                {
                    warnings.Add($"Не удалось скопировать офлайн-куст {hivePath}: {outcome.Error}");
                    TryDeleteDirectory(tempDirectory);
                    return null;
                }

                foreach (var suffix in new[] { ".LOG1", ".LOG2" })
                {
                    if (File.Exists(hivePath + suffix))
                    {
                        LockedFileCopier.Copy(hivePath + suffix, copy + suffix);
                    }
                }

                var load = RunReg("load", $@"HKLM\{mountName}", copy);
                if (load.ExitCode != 0)
                {
                    warnings.Add($"Не удалось загрузить офлайн-куст {hivePath}: {load.Output}");
                    TryDeleteDirectory(tempDirectory);
                    return null;
                }

                var hive = new MountedHive(
                    mountName, tempDirectory, hivePath, HistoricalForensicHelpers.ComputeSha256(hivePath));
                hive._rootKey = Registry.LocalMachine.OpenSubKey(mountName);
                if (hive._rootKey is null)
                {
                    warnings.Add($"Офлайн-куст загружен, но недоступен для чтения: {hivePath}");
                    hive.Dispose();
                    return null;
                }

                return hive;
            }
            catch (Exception exception)
            {
                warnings.Add($"Офлайн-куст {hivePath}: {exception.Message}");
                TryDeleteDirectory(tempDirectory);
                return null;
            }
        }

        public RegistryKey? OpenKey(string relativePath) =>
            string.IsNullOrEmpty(relativePath) ? _rootKey : _rootKey?.OpenSubKey(relativePath);

        public IReadOnlyList<string> SubKeyNames(string relativePath)
        {
            using var key = string.IsNullOrEmpty(relativePath) ? null : _rootKey?.OpenSubKey(relativePath);
            var target = string.IsNullOrEmpty(relativePath) ? _rootKey : key;
            return target?.GetSubKeyNames() ?? [];
        }

        public string ReadString(string relativePath, string valueName)
        {
            using var key = _rootKey?.OpenSubKey(relativePath);
            return key?.GetValue(valueName) as string ?? "";
        }

        public string ReadString(RegistryKey key, string valueName) =>
            key.GetValue(valueName) switch
            {
                string text => text,
                string[] lines => string.Join("; ", lines),
                _ => ""
            };

        public long ReadDword(string relativePath, string valueName)
        {
            using var key = _rootKey?.OpenSubKey(relativePath);
            return key?.GetValue(valueName) switch
            {
                int value => value,
                long value => value,
                _ => 0
            };
        }

        public void Dispose()
        {
            _rootKey?.Dispose();
            _rootKey = null;
            Registry.LocalMachine.Flush();
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var unload = RunReg("unload", $@"HKLM\{_mountName}");
                if (unload.ExitCode == 0)
                {
                    break;
                }

                Thread.Sleep(250 * (attempt + 1));
            }

            TryDeleteDirectory(_tempDirectory);
        }

        private static void TryDeleteDirectory(string path)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, true);
                }
            }
            catch
            {
                // Временная папка не должна ронять аудит: её уберёт следующая чистка temp.
            }
        }

        private static (int ExitCode, string Output) RunReg(string action, string key, string? hive = null)
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "reg.exe",
                    Arguments = hive is null ? $"{action} \"{key}\"" : $"{action} \"{key}\" \"{hive}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            process.Start();
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(15_000))
            {
                try
                {
                    process.Kill(true);
                }
                catch
                {
                    // Процесс мог уже завершиться; важен только код возврата ниже.
                }

                return (-1, "reg.exe timeout");
            }

            Task.WaitAll(stdout, stderr);
            return (process.ExitCode, TextSanitizer.NormalizeDisplay(stdout.Result + stderr.Result, 1000));
        }
    }
}
