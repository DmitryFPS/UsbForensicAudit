using System.IO;

namespace UsbForensicAudit;

public static class AppPaths
{
    private static readonly Lazy<string> LazyDataDirectory = new(ResolveDataDirectory);

    public static string DataDirectory => LazyDataDirectory.Value;

    public static string ExeDirectory { get; } = ResolveExeDirectory();

    public static bool IsPortableLayout { get; private set; }

    public static string ToolsDirectory => Path.Combine(DataDirectory, "tools");

    public static string ProcmonDirectory => Path.Combine(DataDirectory, "procmon");

    public static string LayoutDescription =>
        IsPortableLayout
            ? $"Portable: все данные рядом с программой ({DataDirectory})"
            : $"Данные: {DataDirectory}";

    private static string ResolveExeDirectory()
    {
        if (!string.IsNullOrWhiteSpace(Environment.ProcessPath))
        {
            var directory = Path.GetDirectoryName(Environment.ProcessPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                return directory;
            }
        }

        return AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static string ResolveDataDirectory()
    {
        var portableCandidate = Path.Combine(ExeDirectory, "data");
        if (TryEnsureWritableDirectory(portableCandidate))
        {
            IsPortableLayout = true;
            return portableCandidate;
        }

        IsPortableLayout = false;
        var fallback = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "UsbForensicAudit");
        Directory.CreateDirectory(fallback);
        return fallback;
    }

    private static bool TryEnsureWritableDirectory(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            var probe = Path.Combine(path, $".write-test-{Guid.NewGuid():N}");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
