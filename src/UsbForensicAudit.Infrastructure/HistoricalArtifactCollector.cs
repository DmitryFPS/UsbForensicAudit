using System.Diagnostics;
using System.IO;
using System.Management;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace UsbForensicAudit;

public sealed partial class HistoricalArtifactCollector : IHistoricalArtifactCollector
{
    private const int MaxOfflineLogs = 24;
    private const long MaxOfflineLogBytes = 64L * 1024 * 1024;
    private const int MaxShadowCopies = 8;
    private readonly IAuditStorage _storage;
    private readonly IReadOnlyList<string> _offlineRoots;

    public HistoricalArtifactCollector(IAuditStorage storage)
        : this(storage, DefaultOfflineRoots())
    {
    }

    internal HistoricalArtifactCollector(IAuditStorage storage, IEnumerable<string> offlineRoots)
    {
        _storage = storage;
        _offlineRoots = offlineRoots.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public string ProgressMessage => "Сбор исторических источников, ControlSet и VSS...";

    public void Collect(AuditResult result, CancellationToken cancellationToken = default)
    {
        CollectDeviceMigration(Registry.LocalMachine, "Live SYSTEM", "SYSTEM", result, cancellationToken);
        AnalyzeLiveControlSets(result, cancellationToken);
        DetectLiveTransactionLogs(result);

        foreach (var root in _offlineRoots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CollectOfflineRootCore(root, "Windows.old", result, cancellationToken);
        }

        DiscoverExistingShadowCopies(result, cancellationToken);
        DeviceTransportClassifier.ClassifyAll(result.Devices);
        DeviceIdentityGraph.Process(result.Devices);
    }

    public void CollectOffline(string offlineRoot, AuditResult result, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(offlineRoot);
        ArgumentNullException.ThrowIfNull(result);
        CollectOfflineRootCore(offlineRoot, "Offline root", result, cancellationToken);
        DeviceTransportClassifier.ClassifyAll(result.Devices);
        DeviceIdentityGraph.Process(result.Devices);
    }

    private static void CollectDeviceMigration(
        RegistryKey hiveRoot,
        string sourceLabel,
        string mountedPrefix,
        AuditResult result,
        CancellationToken cancellationToken)
    {
        foreach (var path in HistoricalForensicHelpers.DeviceMigrationPaths())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = StripSystemPrefix(path);
            using var root = hiveRoot.OpenSubKey(CombineRegistryPath(mountedPrefix, relativePath));
            if (root is null)
            {
                continue;
            }

            CollectMigrationRecursive(root, "", $@"{sourceLabel}\{path}", result.Devices, result.Evidence, cancellationToken, 0);
        }
    }

    private static void CollectMigrationRecursive(
        RegistryKey key,
        string relative,
        string provenancePath,
        List<UsbDeviceRecord> devices,
        List<EvidenceRecord> evidence,
        CancellationToken cancellationToken,
        int depth)
    {
        if (depth > 8 || devices.Count > 50_000)
        {
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var identity = NormalizeMigrationIdentity(relative);
        if (IsRelevantMigrationIdentity(identity))
        {
            var rawLastPresent = key.GetValue("LastPresentDate", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            var hasLastPresent = HistoricalForensicHelpers.TryParseLastPresentDate(rawLastPresent, out var lastPresent);
            var record = BuildHistoricalDevice(identity, provenancePath, hasLastPresent ? lastPresent : null, ReadString(key, "ContainerId"));
            devices.Add(record);
            evidence.Add(new EvidenceRecord
            {
                TimestampUtc = hasLastPresent ? lastPresent : record.CollectedAtUtc,
                AcquisitionTimestampUtc = record.CollectedAtUtc,
                Source = "Registry DeviceMigration",
                Provider = "Windows PnP migration",
                Channel = "Registry",
                SourceRecord = identity,
                EvidenceCategory = "Historical residual",
                UserExplanation = "Остаточная запись миграции PnP; не доказывает текущее подключение.",
                DeviceHint = identity,
                Summary = hasLastPresent
                    ? $"DeviceMigration LastPresentDate: {lastPresent:O}"
                    : "DeviceMigration residual без корректного LastPresentDate",
                Provenance = provenancePath,
                RawText = JsonSerializer.Serialize(new
                {
                    RegistryPath = provenancePath,
                    LastPresentDateUtc = hasLastPresent ? lastPresent : (DateTimeOffset?)null,
                    Confidence = hasLastPresent ? "Medium" : "Low",
                    CurrentConnection = false
                })
            });
            return;
        }

        foreach (var name in SafeSubKeyNames(key))
        {
            using var child = SafeOpenSubKey(key, name);
            if (child is null)
            {
                continue;
            }

            var childRelative = string.IsNullOrEmpty(relative) ? name : $@"{relative}\{name}";
            CollectMigrationRecursive(child, childRelative, $@"{provenancePath}\{name}", devices, evidence, cancellationToken, depth + 1);
        }
    }

    private static UsbDeviceRecord BuildHistoricalDevice(
        string identity,
        string provenance,
        DateTimeOffset? lastPresent,
        string containerId)
    {
        var parts = identity.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        var record = new UsbDeviceRecord
        {
            DeviceInstanceId = identity,
            Source = "Registry: DeviceMigration historical residual",
            VisualCategory = "HistoricalResidual",
            UserMeaning = "Остаточная запись DeviceMigration. Это исторический след, а не признак текущего подключения.",
            DeviceType = parts[0].Equals("USBSTOR", StringComparison.OrdinalIgnoreCase) ? "Mass Storage"
                : parts[0].Equals("SWD", StringComparison.OrdinalIgnoreCase) ? "Portable/MTP"
                : parts[0].Equals("SCSI", StringComparison.OrdinalIgnoreCase) ? "SCSI Storage"
                : "USB",
            Serial = parts.Length >= 3 && parts[^1].EndsWith("&0", StringComparison.OrdinalIgnoreCase)
                ? parts[^1][..^2]
                : parts.Length >= 3 ? parts[^1] : "",
            ContainerId = containerId,
            LastSeenUtc = lastPresent,
            DateConfidence = lastPresent.HasValue
                ? "DeviceMigration LastPresentDate (historical residual, medium confidence)"
                : "DeviceMigration residual (low confidence)",
            Connection = "HistoricalResidual",
            ConnectionConfidence = lastPresent.HasValue ? "Medium" : "Low",
            IsCurrentlyConnected = false,
            RawJson = JsonSerializer.Serialize(new
            {
                Provenance = provenance,
                LastPresentDateUtc = lastPresent,
                HistoricalResidual = true,
                CurrentConnection = false
            })
        };

        var vidPid = VidPidRegex().Match(identity);
        if (vidPid.Success)
        {
            record.Vid = vidPid.Groups["vid"].Value.ToUpperInvariant();
            record.Pid = vidPid.Groups["pid"].Value.ToUpperInvariant();
        }

        return record;
    }

    private static void AnalyzeLiveControlSets(AuditResult result, CancellationToken cancellationToken)
    {
        try
        {
            using var system = Registry.LocalMachine.OpenSubKey("SYSTEM");
            if (system is null)
            {
                return;
            }

            var selection = ReadSelect(system);
            var snapshots = ReadControlSetSnapshots(system, cancellationToken);
            var differences = HistoricalForensicHelpers.CompareControlSets(snapshots, selection);
            foreach (var difference in differences.Take(5_000))
            {
                var explanation =
                    "Запись присутствует в другом ControlSet, но отсутствует в выбранном Current. " +
                    "Это может быть нормальной ротацией, откатом LastKnownGood или миграцией ОС; само по себе не подтверждает очистку.";
                result.Evidence.Add(new EvidenceRecord
                {
                    Source = "ControlSet differential",
                    Provider = "SYSTEM registry",
                    Channel = difference.Area,
                    SourceRecord = difference.SourceControlSet,
                    EvidenceCategory = "ControlSet difference",
                    UserExplanation = explanation,
                    DeviceHint = difference.Identity,
                    Summary = $"{difference.Identity}: {difference.SourceControlSet} -> отсутствует в {difference.CurrentControlSet}",
                    Provenance = $@"HKLM\SYSTEM\{difference.SourceControlSet}; HKLM\SYSTEM\Select",
                    RawText = JsonSerializer.Serialize(difference)
                });
                result.CleanupFindings.Add(new CleanupFinding
                {
                    Severity = "Info",
                    Assessment = "Informational",
                    Confidence = "ContextRequired",
                    ActionKind = "ControlSetDifference",
                    Area = "Registry ControlSet",
                    Finding = "Историческая запись отсутствует в текущем ControlSet",
                    Details = $"{difference.Area}: {difference.Identity}. {explanation}"
                });
            }
            if (differences.Count > 5_000)
            {
                result.SourceWarnings.Add($"ControlSet differential: из {differences.Count} различий сохранены первые 5000 по защитному лимиту.");
            }
        }
        catch (Exception ex)
        {
            result.SourceWarnings.Add($"ControlSet differential недоступен: {ex.Message}");
        }
    }

    private static ControlSetSelection ReadSelect(RegistryKey system)
    {
        using var select = system.OpenSubKey("Select");
        if (select is null)
        {
            return new ControlSetSelection("", "", "");
        }

        return HistoricalForensicHelpers.ParseSelect(new Dictionary<string, object?>
        {
            ["Current"] = select.GetValue("Current"),
            ["Default"] = select.GetValue("Default"),
            ["LastKnownGood"] = select.GetValue("LastKnownGood")
        });
    }

    private static IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyCollection<string>>> ReadControlSetSnapshots(
        RegistryKey system,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyCollection<string>>>(StringComparer.OrdinalIgnoreCase);
        foreach (var setName in SafeSubKeyNames(system).Where(IsControlSetName))
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var controlSet = SafeOpenSubKey(system, setName);
            if (controlSet is null)
            {
                continue;
            }

            var areas = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.OrdinalIgnoreCase);
            areas["USB"] = ReadEnumIdentities(controlSet, @"Enum\USB", "USB", cancellationToken);
            areas["USBSTOR"] = ReadEnumIdentities(controlSet, @"Enum\USBSTOR", "USBSTOR", cancellationToken);
            areas["SCSI"] = ReadEnumIdentities(controlSet, @"Enum\SCSI", "SCSI", cancellationToken);
            areas["WPD"] = ReadEnumIdentities(controlSet, @"Enum\SWD\WPDBUSENUM", @"SWD\WPDBUSENUM", cancellationToken);
            areas["usbflags"] = ReadDirectChildNames(controlSet, @"Control\usbflags");
            result[setName] = areas;
        }

        return result;
    }

    private static IReadOnlyCollection<string> ReadEnumIdentities(
        RegistryKey controlSet,
        string path,
        string prefix,
        CancellationToken cancellationToken)
    {
        using var root = controlSet.OpenSubKey(path);
        if (root is null)
        {
            return [];
        }

        var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var familyName in SafeSubKeyNames(root).Take(20_000))
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var family = SafeOpenSubKey(root, familyName);
            if (family is null)
            {
                continue;
            }

            foreach (var instanceName in SafeSubKeyNames(family).Take(5_000))
            {
                identities.Add($@"{prefix}\{familyName}\{instanceName}");
            }
        }

        return identities;
    }

    private static IReadOnlyCollection<string> ReadDirectChildNames(RegistryKey controlSet, string path)
    {
        using var root = controlSet.OpenSubKey(path);
        return root is null
            ? []
            : SafeSubKeyNames(root).Take(20_000).Select(x => $@"usbflags\{x}").ToArray();
    }

    private void CollectOfflineRootCore(
        string root,
        string sourceKind,
        AuditResult result,
        CancellationToken cancellationToken)
    {
        var paths = HistoricalForensicHelpers.BuildOfflinePaths(root);
        if (!Directory.Exists(paths.WindowsDirectory))
        {
            return;
        }

        CollectOfflineSetupApi(paths.InfDirectory, sourceKind, result, cancellationToken);
        LoadOfflineSystemCopy(paths.SystemHive, sourceKind, result, cancellationToken);
        LoadOfflineSoftwareCopy(paths.SoftwareHive, sourceKind, result, cancellationToken);
        AcquireTransactionLogs(paths.SystemHive, $"{sourceKind} SYSTEM", result);
        AcquireTransactionLogs(paths.SoftwareHive, $"{sourceKind} SOFTWARE", result);
        DetectOfflineNtUserLogs(root, sourceKind, result);
    }

    private static void CollectOfflineSetupApi(
        string infDirectory,
        string sourceKind,
        AuditResult result,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(infDirectory))
        {
            return;
        }

        string[] files;
        try
        {
            files = Directory.EnumerateFiles(infDirectory, "setupapi.dev.log*", SearchOption.TopDirectoryOnly)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .Take(MaxOfflineLogs)
                .ToArray();
        }
        catch (Exception ex)
        {
            result.SourceWarnings.Add($"{sourceKind} SetupAPI enumeration: {ex.Message}");
            return;
        }

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var info = new FileInfo(file);
                if (info.Length > MaxOfflineLogBytes)
                {
                    result.SourceWarnings.Add($"{sourceKind}: {file} пропущен: размер {info.Length} превышает лимит {MaxOfflineLogBytes}.");
                    continue;
                }

                var acquiredAt = DateTimeOffset.UtcNow;
                var sha256 = HistoricalForensicHelpers.ComputeSha256(file);
                using var reader = File.OpenText(file);
                foreach (var record in SetupApiLogParser.Parse(reader, $"{sourceKind}: {Path.GetFileName(file)}", file))
                {
                    record.AcquisitionTimestampUtc = acquiredAt;
                    record.SourceSha256 = sha256;
                    record.Provenance = $"Read-only source path: {file}";
                    result.Evidence.Add(record);
                }
            }
            catch (Exception ex)
            {
                result.SourceWarnings.Add($"{sourceKind}: ошибка чтения {file}: {ex.Message}");
            }
        }
    }

    private void LoadOfflineSystemCopy(
        string sourceHive,
        string sourceKind,
        AuditResult result,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(sourceHive))
        {
            return;
        }

        var workDirectory = Path.Combine(_storage.DataDirectory, "forensic-temp", Guid.NewGuid().ToString("N"));
        var mountName = $"UFA_HIST_{Guid.NewGuid():N}";
        var mounted = false;
        try
        {
            Directory.CreateDirectory(workDirectory);
            var copiedHive = CopyHiveFamily(sourceHive, workDirectory);
            var sourceHash = HistoricalForensicHelpers.ComputeSha256(sourceHive);
            var load = RunReg("load", $@"HKLM\{mountName}", copiedHive);
            if (load.ExitCode != 0)
            {
                result.SourceWarnings.Add($"{sourceKind} SYSTEM copy load failed: {load.Output}");
                return;
            }

            mounted = true;
            using var mountedRoot = Registry.LocalMachine.OpenSubKey(mountName);
            if (mountedRoot is null)
            {
                return;
            }

            CollectDeviceMigration(mountedRoot, $"{sourceKind} SYSTEM", "", result, cancellationToken);
            var selection = ReadSelect(mountedRoot);
            if (!string.IsNullOrWhiteSpace(selection.Current))
            {
                using var selectedMigration = mountedRoot.OpenSubKey(
                    $@"{selection.Current}\Control\DeviceMigration\Devices");
                if (selectedMigration is not null)
                {
                    CollectMigrationRecursive(
                        selectedMigration,
                        "",
                        $@"{sourceKind} SYSTEM\{selection.Current}\Control\DeviceMigration\Devices",
                        result.Devices,
                        result.Evidence,
                        cancellationToken,
                        0);
                }
            }
            result.Evidence.Add(new EvidenceRecord
            {
                Source = $"{sourceKind} offline hive",
                Provider = "Copied SYSTEM hive",
                Channel = "Registry",
                SourceFile = sourceHive,
                SourceSha256 = sourceHash,
                EvidenceCategory = "Offline acquisition",
                Summary = $"Offline SYSTEM loaded from a disposable copy; Current={selection.Current}",
                UserExplanation = "Исходный hive не загружался и не изменялся; анализ выполнен на временной копии.",
                Provenance = $"Source={sourceHive}; Copy={copiedHive}",
                RawText = JsonSerializer.Serialize(new
                {
                    selection.Current,
                    selection.Default,
                    selection.LastKnownGood,
                    TransactionLogs = HistoricalForensicHelpers.GetTransactionLogStatus(sourceHive)
                })
            });
        }
        catch (Exception ex)
        {
            result.SourceWarnings.Add($"{sourceKind} offline SYSTEM: {ex.Message}");
        }
        finally
        {
            if (mounted)
            {
                Registry.LocalMachine.Flush();
                var unload = RunReg("unload", $@"HKLM\{mountName}");
                if (unload.ExitCode != 0)
                {
                    result.SourceWarnings.Add($"Не удалось выгрузить временную копию HKLM\\{mountName}: {unload.Output}");
                }
            }

            TryDeleteDirectory(workDirectory, result.SourceWarnings);
        }
    }

    private void LoadOfflineSoftwareCopy(
        string sourceHive,
        string sourceKind,
        AuditResult result,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(sourceHive))
        {
            return;
        }

        var workDirectory = Path.Combine(_storage.DataDirectory, "forensic-temp", Guid.NewGuid().ToString("N"));
        var mountName = $"UFA_SOFT_{Guid.NewGuid():N}";
        var mounted = false;
        try
        {
            Directory.CreateDirectory(workDirectory);
            var copiedHive = CopyHiveFamily(sourceHive, workDirectory);
            var sourceHash = HistoricalForensicHelpers.ComputeSha256(sourceHive);
            var load = RunReg("load", $@"HKLM\{mountName}", copiedHive);
            if (load.ExitCode != 0)
            {
                result.SourceWarnings.Add($"{sourceKind} SOFTWARE copy load failed: {load.Output}");
                return;
            }

            mounted = true;
            using var root = Registry.LocalMachine.OpenSubKey(
                $@"{mountName}\Microsoft\Windows Portable Devices\Devices");
            if (root is not null)
            {
                foreach (var keyName in SafeSubKeyNames(root).Take(10_000))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using var key = SafeOpenSubKey(root, keyName);
                    if (key is null)
                    {
                        continue;
                    }

                    var rawIdentity = FirstNotEmpty(
                        ReadString(key, "DeviceInstanceId"),
                        ReadString(key, "DeviceID"),
                        keyName);
                    var parsed = UsbRegistryForensicHelpers.ParseWpdIdentity(rawIdentity);
                    var identity = string.IsNullOrWhiteSpace(parsed.DeviceInstanceId)
                        ? $@"WPD\{keyName}"
                        : parsed.DeviceInstanceId;
                    result.Devices.Add(new UsbDeviceRecord
                    {
                        DeviceInstanceId = identity,
                        Source = $"{sourceKind} SOFTWARE: Portable Devices historical residual",
                        VisualCategory = "HistoricalResidual",
                        UserMeaning = "Историческая запись Portable Devices из offline SOFTWARE; не доказывает текущее подключение.",
                        DeviceType = "Portable/MTP",
                        Serial = parsed.Serial,
                        FriendlyName = FirstNotEmpty(ReadString(key, "FriendlyName"), ReadString(key, "Name")),
                        Manufacturer = FirstNotEmpty(ReadString(key, "Manufacturer"), ReadString(key, "Mfg")),
                        Product = FirstNotEmpty(ReadString(key, "Description"), ReadString(key, "DeviceDesc"), ReadString(key, "Model")),
                        ContainerId = FirstNotEmpty(ReadString(key, "ContainerId"), ReadString(key, "ContainerID")),
                        RegistryLastWriteUtc = RegistryKeyTimestamps.GetLastWriteUtc(key),
                        IsCurrentlyConnected = false,
                        Connection = "HistoricalResidual",
                        ConnectionConfidence = "Medium",
                        RawJson = JsonSerializer.Serialize(new
                        {
                            SourceHive = sourceHive,
                            SourceSha256 = sourceHash,
                            CopiedHive = copiedHive,
                            RegistryPath = $@"Microsoft\Windows Portable Devices\Devices\{keyName}",
                            HistoricalResidual = true
                        })
                    });
                }
            }

            result.Evidence.Add(new EvidenceRecord
            {
                Source = $"{sourceKind} offline hive",
                Provider = "Copied SOFTWARE hive",
                Channel = "Registry",
                SourceFile = sourceHive,
                SourceSha256 = sourceHash,
                EvidenceCategory = "Offline acquisition",
                Summary = "Offline SOFTWARE loaded from a disposable copy",
                UserExplanation = "Исходный hive не загружался и не изменялся; анализ Portable Devices выполнен на временной копии.",
                Provenance = $"Source={sourceHive}; Copy={copiedHive}",
                RawText = JsonSerializer.Serialize(new
                {
                    TransactionLogs = HistoricalForensicHelpers.GetTransactionLogStatus(sourceHive)
                })
            });
        }
        catch (Exception ex)
        {
            result.SourceWarnings.Add($"{sourceKind} offline SOFTWARE: {ex.Message}");
        }
        finally
        {
            if (mounted)
            {
                Registry.LocalMachine.Flush();
                var unload = RunReg("unload", $@"HKLM\{mountName}");
                if (unload.ExitCode != 0)
                {
                    result.SourceWarnings.Add($"Не удалось выгрузить временную копию HKLM\\{mountName}: {unload.Output}");
                }
            }

            TryDeleteDirectory(workDirectory, result.SourceWarnings);
        }
    }

    private void DetectOfflineNtUserLogs(string offlineRoot, string sourceKind, AuditResult result)
    {
        var paths = HistoricalForensicHelpers.BuildOfflinePaths(offlineRoot);
        var root = Directory.GetParent(paths.WindowsDirectory)?.FullName;
        if (string.IsNullOrWhiteSpace(root))
        {
            return;
        }

        var usersRoot = Path.Combine(root, "Users");
        if (!Directory.Exists(usersRoot))
        {
            return;
        }

        try
        {
            foreach (var profile in Directory.EnumerateDirectories(usersRoot).Take(256))
            {
                AcquireTransactionLogs(
                    Path.Combine(profile, "NTUSER.DAT"),
                    $"{sourceKind} NTUSER {Path.GetFileName(profile)}",
                    result);
            }
        }
        catch (Exception ex)
        {
            result.SourceWarnings.Add($"{sourceKind} NTUSER transaction log discovery: {ex.Message}");
        }
    }

    private void DetectLiveTransactionLogs(AuditResult result)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        AcquireTransactionLogs(Path.Combine(windows, "System32", "config", "SYSTEM"), "Live SYSTEM", result);

        var users = ResolveLiveProfilesDirectory();
        if (string.IsNullOrWhiteSpace(users))
        {
            result.SourceWarnings.Add("Не удалось определить каталог пользовательских профилей Windows.");
            return;
        }

        if (!Directory.Exists(users))
        {
            return;
        }

        try
        {
            foreach (var profile in Directory.EnumerateDirectories(users).Take(256))
            {
                AcquireTransactionLogs(Path.Combine(profile, "NTUSER.DAT"), $"NTUSER {Path.GetFileName(profile)}", result);
            }
        }
        catch (Exception ex)
        {
            result.SourceWarnings.Add($"NTUSER transaction log discovery: {ex.Message}");
        }
    }

    private static string? ResolveLiveProfilesDirectory()
    {
        try
        {
            using var profileList = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            var configured = profileList?.GetValue("ProfilesDirectory")?.ToString();
            if (!string.IsNullOrWhiteSpace(configured))
            {
                return Environment.ExpandEnvironmentVariables(configured);
            }
        }
        catch (Exception exception)
        {
            AppLog.Error(exception, "ProfilesDirectory lookup failed");
        }

        var currentProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return string.IsNullOrWhiteSpace(currentProfile)
            ? null
            : Directory.GetParent(currentProfile)?.FullName;
    }

    private void AcquireTransactionLogs(string hivePath, string label, AuditResult result)
    {
        var logs = new[] { hivePath + ".LOG1", hivePath + ".LOG2" }.Where(File.Exists).ToArray();
        if (logs.Length == 0)
        {
            return;
        }

        var acquisitionRoot = Path.Combine(
            _storage.DataDirectory,
            "forensic-acquisitions",
            result.StartedAtUtc.UtcDateTime.ToString("yyyyMMddTHHmmssfff"));
        Directory.CreateDirectory(acquisitionRoot);
        foreach (var log in logs)
        {
            try
            {
                var sourceHash = HistoricalForensicHelpers.ComputeSha256(log);
                var safeName = $"{SanitizeFileName(label)}-{Path.GetFileName(log)}-{sourceHash[..12]}";
                var destination = Path.Combine(acquisitionRoot, safeName);
                File.Copy(log, destination, overwrite: false);
                var copiedHash = HistoricalForensicHelpers.ComputeSha256(destination);
                result.Evidence.Add(new EvidenceRecord
                {
                    Source = "Registry transaction log acquisition",
                    Provider = "File copy",
                    Channel = "Registry transaction log",
                    SourceFile = log,
                    SourceSha256 = sourceHash,
                    EvidenceCategory = "Coverage limitation",
                    Summary = $"{label}: {HistoricalForensicHelpers.TransactionLogsPresentNotReplayed}",
                    UserExplanation = "LOG1/LOG2 безопасно скопирован, но deleted-cell carving и доказанный replay не выполнялись.",
                    Provenance = $"Source={log}; Copy={destination}; CopySHA256={copiedHash}",
                    RawText = HistoricalForensicHelpers.TransactionLogsPresentNotReplayed
                });
            }
            catch (Exception ex)
            {
                result.SourceWarnings.Add($"Не удалось скопировать transaction log {log}: {ex.Message}");
            }
        }
    }

    private void DiscoverExistingShadowCopies(AuditResult result, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            var options = new System.Management.EnumerationOptions
            {
                ReturnImmediately = false,
                Rewindable = false,
                Timeout = TimeSpan.FromSeconds(8)
            };
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"\\.\root\cimv2"),
                new ObjectQuery("SELECT ID, DeviceObject, InstallDate, VolumeName FROM Win32_ShadowCopy"),
                options);
            using var shadows = searcher.Get();
            var dedup = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var count = 0;
            foreach (ManagementObject shadow in shadows)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (count++ >= MaxShadowCopies)
                {
                    result.SourceWarnings.Add($"VSS: обработаны первые {MaxShadowCopies} существующих snapshot; остальные пропущены по лимиту.");
                    break;
                }

                var rawPath = shadow["DeviceObject"]?.ToString();
                if (!HistoricalForensicHelpers.TryParseShadowDevicePath(rawPath, out var devicePath))
                {
                    continue;
                }

                result.Evidence.Add(new EvidenceRecord
                {
                    Source = "VSS discovery",
                    Provider = "Win32_ShadowCopy",
                    Channel = "Existing snapshot",
                    SourceRecord = shadow["ID"]?.ToString() ?? "",
                    EvidenceCategory = "Historical source",
                    Summary = $"Обнаружена существующая shadow copy: {devicePath}",
                    UserExplanation = "Snapshot только перечислен; новый snapshot не создавался.",
                    Provenance = "WMI read-only query Win32_ShadowCopy",
                    RawText = JsonSerializer.Serialize(new
                    {
                        DeviceObject = devicePath,
                        InstallDate = shadow["InstallDate"]?.ToString(),
                        VolumeName = shadow["VolumeName"]?.ToString()
                    })
                });

                var windowsRoot = Path.Combine(devicePath, "Windows");
                CollectSnapshotFiles(windowsRoot, result, dedup, cancellationToken);
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or IOException)
        {
            result.SourceWarnings.Add($"VSS discovery недоступен (scan продолжен): {ex.Message}");
        }
    }

    private static void CollectSnapshotFiles(
        string windowsRoot,
        AuditResult result,
        HashSet<string> dedup,
        CancellationToken cancellationToken)
    {
        var paths = HistoricalForensicHelpers.BuildOfflinePaths(windowsRoot);
        if (Directory.Exists(paths.InfDirectory))
        {
            string[] logs;
            try
            {
                logs = Directory.EnumerateFiles(paths.InfDirectory, "setupapi.dev.log*", SearchOption.TopDirectoryOnly)
                    .Take(8)
                    .ToArray();
            }
            catch
            {
                logs = [];
            }

            foreach (var log in logs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (new FileInfo(log).Length > MaxOfflineLogBytes)
                    {
                        continue;
                    }

                    var hash = HistoricalForensicHelpers.ComputeSha256(log);
                    var key = HistoricalForensicHelpers.SnapshotDedupKey(hash, Path.GetFileName(log));
                    if (!dedup.Add(key))
                    {
                        continue;
                    }

                    using var reader = File.OpenText(log);
                    foreach (var record in SetupApiLogParser.Parse(reader, $"VSS: {Path.GetFileName(log)}", log))
                    {
                        record.SourceSha256 = hash;
                        record.AcquisitionTimestampUtc = DateTimeOffset.UtcNow;
                        record.Provenance = $"Existing VSS path (read-only): {log}";
                        result.Evidence.Add(record);
                    }
                }
                catch
                {
                    // Недоступный файл конкретного snapshot не должен прерывать общий scan.
                }
            }
        }

        foreach (var hive in new[] { paths.SystemHive, paths.SoftwareHive }.Where(File.Exists))
        {
            try
            {
                var hash = HistoricalForensicHelpers.ComputeSha256(hive);
                if (!dedup.Add(HistoricalForensicHelpers.SnapshotDedupKey(hash, Path.GetFileName(hive))))
                {
                    continue;
                }

                result.Evidence.Add(new EvidenceRecord
                {
                    Source = "VSS registry hive discovery",
                    Provider = "Existing shadow copy",
                    Channel = "Registry hive",
                    SourceFile = hive,
                    SourceSha256 = hash,
                    EvidenceCategory = "Historical source",
                    Summary = $"Доступен hive в существующей shadow copy: {Path.GetFileName(hive)}",
                    UserExplanation = "Hive обнаружен и хеширован без загрузки и без изменения snapshot.",
                    Provenance = $"Existing VSS path (read-only): {hive}"
                });
            }
            catch
            {
                // Best effort в жёстко ограниченном наборе известных путей.
            }
        }
    }

    private static string CopyHiveFamily(string sourceHive, string destinationDirectory)
    {
        var destinationHive = Path.Combine(destinationDirectory, Path.GetFileName(sourceHive));
        File.Copy(sourceHive, destinationHive, overwrite: false);
        foreach (var suffix in new[] { ".LOG1", ".LOG2" })
        {
            var sourceLog = sourceHive + suffix;
            if (File.Exists(sourceLog))
            {
                File.Copy(sourceLog, destinationHive + suffix, overwrite: false);
            }
        }

        return destinationHive;
    }

    private static (int ExitCode, string Output) RunReg(string action, string keyPath, string? hivePath = null)
    {
        var arguments = hivePath is null
            ? $"{action} \"{keyPath}\""
            : $"{action} \"{keyPath}\" \"{hivePath}\"";
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };
        process.Start();
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15_000))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Best effort cleanup.
            }
            return (-1, "reg.exe timeout");
        }

        Task.WaitAll(outputTask, errorTask);
        return (process.ExitCode, TextSanitizer.NormalizeDisplay(outputTask.Result + errorTask.Result, 1000));
    }

    private static string NormalizeMigrationIdentity(string value)
    {
        var normalized = value.Replace('#', '\\').Trim('\\');
        var match = MigrationIdentityRegex().Match(normalized);
        return match.Success ? match.Value : normalized;
    }

    private static bool IsRelevantMigrationIdentity(string identity) =>
        MigrationIdentityRegex().IsMatch(identity);

    private static string StripSystemPrefix(string path) =>
        path.StartsWith(@"SYSTEM\", StringComparison.OrdinalIgnoreCase) ? path[7..] : path;

    private static string CombineRegistryPath(string prefix, string path) =>
        string.IsNullOrWhiteSpace(prefix) ? path : $@"{prefix.TrimEnd('\\')}\{path.TrimStart('\\')}";

    private static string ReadString(RegistryKey key, string name) =>
        key.GetValue(name, "") switch
        {
            string text => text,
            string[] values => string.Join("; ", values),
            _ => ""
        };

    private static string FirstNotEmpty(params string[] values) =>
        values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim() ?? "";

    private static string[] SafeSubKeyNames(RegistryKey key)
    {
        try
        {
            return key.GetSubKeyNames();
        }
        catch
        {
            return [];
        }
    }

    private static RegistryKey? SafeOpenSubKey(RegistryKey key, string name)
    {
        try
        {
            return key.OpenSubKey(name);
        }
        catch
        {
            return null;
        }
    }

    private static bool IsControlSetName(string value) =>
        value.Length == 13
        && value.StartsWith("ControlSet", StringComparison.OrdinalIgnoreCase)
        && int.TryParse(value.AsSpan(10), out _);

    private static string SanitizeFileName(string value) =>
        string.Concat(value.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));

    private static void TryDeleteDirectory(string path, List<string> warnings)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (Exception ex)
        {
            warnings.Add($"Не удалось удалить forensic-temp {path}: {ex.Message}");
        }
    }

    private static IReadOnlyList<string> DefaultOfflineRoots()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var drive = Path.GetPathRoot(windows) ?? @"C:\";
        return [Path.Combine(drive, "Windows.old")];
    }

    [GeneratedRegex(@"VID_(?<vid>[0-9A-F]{4})&PID_(?<pid>[0-9A-F]{4})", RegexOptions.IgnoreCase)]
    private static partial Regex VidPidRegex();

    [GeneratedRegex(@"(?:USBSTOR|USB|SCSI|SWD)\\[^\\]+\\[^\\]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MigrationIdentityRegex();
}
