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
        if (!File.Exists(sourceHive)) return;
        var tempDirectory = Path.Combine(Path.GetTempPath(), "UsbForensicAudit", Guid.NewGuid().ToString("N"));
        var mount = $"UFA_USER_{Guid.NewGuid():N}";
        var loaded = false;
        try
        {
            Directory.CreateDirectory(tempDirectory);
            var copy = Path.Combine(tempDirectory, Path.GetFileName(sourceHive));
            File.Copy(sourceHive, copy, false);
            foreach (var suffix in new[] { ".LOG1", ".LOG2" })
            {
                if (File.Exists(sourceHive + suffix)) File.Copy(sourceHive + suffix, copy + suffix, false);
            }
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
            foreach (var record in evidence.Where(x => x.UserSid == profile.Sid
                                                       && x.Provenance.Contains(mount, StringComparison.OrdinalIgnoreCase)))
            {
                record.SourceFile = sourceHive;
                record.SourceSha256 = HistoricalForensicHelpers.ComputeSha256(sourceHive);
                record.Provenance = $"Source={sourceHive}; disposable copy={copy}; registry={record.Provenance}";
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
                Registry.Users.Flush();
                var unload = RunReg("unload", $@"HKU\{mount}");
                if (unload.ExitCode != 0) warnings.Add($"Offline hive unload HKU\\{mount}: {unload.Output}");
            }
            try { if (Directory.Exists(tempDirectory)) Directory.Delete(tempDirectory, true); }
            catch (Exception ex) { warnings.Add($"Offline hive temp cleanup: {ex.Message}"); }
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
            try { process.Kill(true); } catch { }
            return (-1, "reg.exe timeout");
        }
        Task.WaitAll(stdout, stderr);
        return (process.ExitCode, TextSanitizer.NormalizeDisplay(stdout.Result + stderr.Result, 1000));
    }
}
