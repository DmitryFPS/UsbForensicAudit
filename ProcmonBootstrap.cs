using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;

namespace UsbForensicAudit;

public static class ProcmonBootstrap
{
    private const string EmbeddedResourceName = "UsbForensicAudit.Tools.Procmon64.exe";
    private const string DownloadUrl = "https://download.sysinternals.com/files/ProcessMonitor.zip";
    private const string ProcmonExeName = "Procmon64.exe";

    public static string ToolsDirectory => AppPaths.ToolsDirectory;
    public static string ProcmonPath => Path.Combine(ToolsDirectory, ProcmonExeName);

    public static bool IsAvailable() =>
        File.Exists(ProcmonPath) || HasEmbeddedProcmon() || FindSidecarProcmon() is not null;

    public static async Task<string> EnsureProcmonAsync(IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(ToolsDirectory);

        if (File.Exists(ProcmonPath))
        {
            return ProcmonPath;
        }

        progress?.Report("Подготовка Procmon…");

        var sidecar = FindSidecarProcmon();
        if (sidecar is not null && TryInstallFromFile(sidecar))
        {
            progress?.Report("Procmon скопирован из папки рядом с программой.");
            return ProcmonPath;
        }

        if (TryExtractEmbeddedProcmon())
        {
            progress?.Report("Procmon распакован из состава программы (работает без интернета).");
            return ProcmonPath;
        }

        progress?.Report("Загрузка Process Monitor с сайта Microsoft Sysinternals…");
        await DownloadProcmonAsync(cancellationToken);
        if (!File.Exists(ProcmonPath))
        {
            throw new InvalidOperationException(
                "Procmon64.exe не найден. В portable-сборке он встроен в UsbForensicAudit.exe и распаковывается при первом запуске трассировки. " +
                "Если вы собирали программу сами — выполните build-exe.ps1 на ПК с интернетом. " +
                $"Либо положите Procmon64.exe вручную в папку {ToolsDirectory}.");
        }

        return ProcmonPath;
    }

    private static bool HasEmbeddedProcmon()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(EmbeddedResourceName);
        return stream is not null;
    }

    private static string? FindSidecarProcmon()
    {
        foreach (var candidate in EnumerateSidecarCandidates())
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static IEnumerable<string> EnumerateSidecarCandidates()
    {
        foreach (var baseDir in EnumerateApplicationDirectories())
        {
            yield return Path.Combine(baseDir, "tools", ProcmonExeName);
            yield return Path.Combine(baseDir, ProcmonExeName);
        }
    }

    private static IEnumerable<string> EnumerateApplicationDirectories()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (TryAddDirectory(seen, AppContext.BaseDirectory))
        {
            yield return AppContext.BaseDirectory;
        }

        var processPath = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(processPath))
        {
            var processDirectory = Path.GetDirectoryName(processPath);
            if (TryAddDirectory(seen, processDirectory))
            {
                yield return processDirectory!;
            }
        }
    }

    private static bool TryAddDirectory(HashSet<string> seen, string? directory) =>
        !string.IsNullOrWhiteSpace(directory) && seen.Add(directory);

    private static bool TryInstallFromFile(string sourcePath)
    {
        try
        {
            File.Copy(sourcePath, ProcmonPath, overwrite: true);
            return File.Exists(ProcmonPath);
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Failed to copy sidecar Procmon from " + sourcePath);
            return false;
        }
    }

    private static bool TryExtractEmbeddedProcmon()
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(EmbeddedResourceName);
        if (stream is null)
        {
            return false;
        }

        using var file = File.Create(ProcmonPath);
        stream.CopyTo(file);
        return true;
    }

    private static async Task DownloadProcmonAsync(CancellationToken cancellationToken)
    {
        var zipPath = Path.Combine(ToolsDirectory, "ProcessMonitor.zip");
        using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(3) };
        await using (var remote = await client.GetStreamAsync(DownloadUrl, cancellationToken))
        await using (var local = File.Create(zipPath))
        {
            await remote.CopyToAsync(local, cancellationToken);
        }

        var extractDir = Path.Combine(ToolsDirectory, "ProcessMonitorExtract");
        if (Directory.Exists(extractDir))
        {
            Directory.Delete(extractDir, true);
        }

        Directory.CreateDirectory(extractDir);
        ZipFile.ExtractToDirectory(zipPath, extractDir);

        var extracted = Directory.GetFiles(extractDir, ProcmonExeName, SearchOption.AllDirectories).FirstOrDefault()
                        ?? Directory.GetFiles(extractDir, "Procmon.exe", SearchOption.AllDirectories).FirstOrDefault();
        if (extracted is null)
        {
            throw new InvalidOperationException("В архиве Process Monitor не найден Procmon64.exe.");
        }

        File.Copy(extracted, ProcmonPath, overwrite: true);
        try
        {
            File.Delete(zipPath);
            Directory.Delete(extractDir, true);
        }
        catch
        {
            // Best effort cleanup.
        }
    }
}
