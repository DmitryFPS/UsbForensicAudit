using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Security;

namespace UsbForensicAudit;

public static class ProcmonBootstrap
{
    private const string EmbeddedResourceName = "UsbForensicAudit.Tools.Procmon64.exe";
    private const string DownloadUrl = "https://download.sysinternals.com/files/ProcessMonitor.zip";
    private const string ProcmonExeName = "Procmon64.exe";
    private const long MaximumDownloadBytes = 100 * 1024 * 1024;
    private const long MaximumExecutableBytes = 50 * 1024 * 1024;

    public static string ToolsDirectory => AppPaths.ToolsDirectory;
    public static string ProcmonPath => Path.Combine(ToolsDirectory, ProcmonExeName);

    public static bool IsAvailable() =>
        File.Exists(ProcmonPath) || HasEmbeddedProcmon() || FindSidecarProcmon() is not null;

    public static async Task<string> EnsureProcmonAsync(IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(ToolsDirectory);

        if (File.Exists(ProcmonPath))
        {
            EnsureTrustedProcmon(ProcmonPath);
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
            EnsureTrustedProcmon(sourcePath);
            InstallAtomically(sourcePath);
            EnsureTrustedProcmon(ProcmonPath);
            return true;
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

        var temporaryPath = ProcmonPath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            using (var file = File.Create(temporaryPath))
            {
                stream.CopyTo(file);
                file.Flush(flushToDisk: true);
            }

            EnsureTrustedProcmon(temporaryPath);
            File.Move(temporaryPath, ProcmonPath, overwrite: true);
            return true;
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static async Task DownloadProcmonAsync(CancellationToken cancellationToken)
    {
        var zipPath = Path.Combine(ToolsDirectory, "ProcessMonitor.zip");
        using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(3) };
        using var response = await client.GetAsync(
            DownloadUrl,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > MaximumDownloadBytes)
        {
            throw new InvalidDataException("Архив Process Monitor превышает допустимый размер.");
        }

        await using (var remote = await response.Content.ReadAsStreamAsync(cancellationToken))
        await using (var local = File.Create(zipPath))
        {
            await CopyWithLimitAsync(remote, local, MaximumDownloadBytes, cancellationToken);
            await local.FlushAsync(cancellationToken);
        }

        var temporaryExe = ProcmonPath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            using var archive = ZipFile.OpenRead(zipPath);
            var entry = archive.Entries.FirstOrDefault(candidate =>
                            Path.GetFileName(candidate.FullName).Equals(ProcmonExeName, StringComparison.OrdinalIgnoreCase))
                        ?? archive.Entries.FirstOrDefault(candidate =>
                            Path.GetFileName(candidate.FullName).Equals("Procmon.exe", StringComparison.OrdinalIgnoreCase));
            if (entry is null || entry.Length <= 0 || entry.Length > MaximumExecutableBytes)
            {
                throw new InvalidDataException("В архиве нет допустимого Procmon64.exe.");
            }

            await using (var source = entry.Open())
            await using (var destination = File.Create(temporaryExe))
            {
                await CopyWithLimitAsync(source, destination, MaximumExecutableBytes, cancellationToken);
                await destination.FlushAsync(cancellationToken);
            }

            EnsureTrustedProcmon(temporaryExe);
            File.Move(temporaryExe, ProcmonPath, overwrite: true);
        }
        finally
        {
            TryDelete(zipPath);
            TryDelete(temporaryExe);
        }
    }

    private static async Task CopyWithLimitAsync(
        Stream source,
        Stream destination,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[81_920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
        {
            total += read;
            if (total > maximumBytes)
            {
                throw new InvalidDataException("Загружаемый файл превышает допустимый размер.");
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    private static void InstallAtomically(string sourcePath)
    {
        var temporaryPath = ProcmonPath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            File.Copy(sourcePath, temporaryPath, overwrite: true);
            File.Move(temporaryPath, ProcmonPath, overwrite: true);
        }
        finally
        {
            TryDelete(temporaryPath);
        }
    }

    private static void EnsureTrustedProcmon(string path)
    {
        if (!AuthenticodeTrust.IsTrustedMicrosoftBinary(path))
        {
            throw new SecurityException(
                $"Procmon отклонён: отсутствует действительная подпись Microsoft ({path}).");
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception exception)
        {
            AppLog.Error(exception, "Temporary Procmon cleanup failed: " + path);
        }
    }
}
