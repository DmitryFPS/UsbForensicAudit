using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace UsbForensicAudit;

public sealed class OfflineHiveCollector : IEvidenceCollector
{
    public string ProgressMessage => "Безопасный offline-анализ копий NTUSER.DAT и UsrClass.dat...";
    public bool ShouldRun => true;

    public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings)
    {
        var evidence = new List<EvidenceRecord>();
        var profiles = UserArtifactCollector.ResolveProfiles(warnings);
        var existingProfiles = profiles.Values.Where(x => Directory.Exists(x.ProfilePath)).ToArray();
        if (existingProfiles.Length > 256)
        {
            warnings.Add("Offline user hives: достигнут лимит 256 профилей.");
        }
        foreach (var profile in existingProfiles.Take(256))
        {
            LoadCopyAndCollect(Path.Combine(profile.ProfilePath, "NTUSER.DAT"), profile, false, evidence, warnings);
            LoadCopyAndCollect(
                Path.Combine(profile.ProfilePath, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"),
                profile, true, evidence, warnings);
        }
        return evidence;
    }

    private static void LoadCopyAndCollect(
        string sourceHive,
        UserProfileIdentity profile,
        bool usrClass,
        List<EvidenceRecord> evidence,
        List<string> warnings)
    {
        if (!File.Exists(sourceHive))
        {
            return;
        }

        var tempDirectory = Path.Combine(Path.GetTempPath(), "UsbForensicAudit", Guid.NewGuid().ToString("N"));
        var mount = $"UFA_USER_{Guid.NewGuid():N}";
        var loaded = false;
        try
        {
            Directory.CreateDirectory(tempDirectory);
            var copy = Path.Combine(tempDirectory, Path.GetFileName(sourceHive));

            // Куст активного пользователя открыт системой, поэтому обычное
            // копирование на нём падает и профиль выпадает из анализа.
            var outcome = LockedFileCopier.CopyHiveFamily(sourceHive, copy);
            if (!outcome.Success)
            {
                warnings.Add($"Не удалось скопировать куст {sourceHive}: {outcome.Error}");
                return;
            }

            var sourceHash = HistoricalForensicHelpers.ComputeSha256(copy);
            var firstRecord = evidence.Count;
            var load = RunReg("load", $@"HKU\{mount}", copy);
            if (load.ExitCode != 0)
            {
                warnings.Add($"Offline hive copy load failed {sourceHive}: {load.Output}");
                return;
            }
            loaded = true;
            if (usrClass)
            {
                UserArtifactCollector.CollectShellBags(
                    Registry.Users, mount, profile, "Offline UsrClass.dat", evidence);
            }
            else
            {
                UserArtifactCollector.CollectMountedNtUser(
                    Registry.Users, mount, profile, "Offline NTUSER.DAT", evidence);
            }
            foreach (var record in evidence.Skip(firstRecord))
            {
                record.SourceFile = sourceHive;
                record.SourceSha256 = sourceHash;
                record.Provenance = $"Source={sourceHive}; acquisition={outcome.Method}; acquired copy SHA256={sourceHash}; disposable copy={copy}; registry={record.Provenance}";
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Offline hive {sourceHive}: {ex.Message}");
        }
        finally
        {
            if (loaded)
            {
                var unload = RunRegWithRetry("unload", $@"HKU\{mount}");
                if (unload.ExitCode != 0)
                {
                    warnings.Add($"Offline hive unload HKU\\{mount}: {unload.Output}");
                }
            }
            try
            {
                if (Directory.Exists(tempDirectory))
                {
                    Directory.Delete(tempDirectory, true);
                }
            }
            catch (Exception ex) { warnings.Add($"Offline hive temp cleanup: {ex.Message}"); }
        }
    }

    private static (int ExitCode, string Output) RunReg(string action, string key, string? hive = null)
        => RegistryHiveCommands.Run(action, key, hive);

    private static (int ExitCode, string Output) RunRegWithRetry(string action, string key)
    {
        (int ExitCode, string Output) result = (-1, "not started");
        for (var attempt = 0; attempt < 3; attempt++)
        {
            result = RunReg(action, key);
            if (result.ExitCode == 0)
            {
                return result;
            }

            Thread.Sleep(250 * (attempt + 1));
        }

        return result;
    }
}
