using System.IO;
using System.Text;

namespace UsbForensicAudit;

public static class AppLog
{
    private static readonly object Sync = new();

    public static string DataDirectory => AppPaths.DataDirectory;
    public static string LogPath { get; } = Path.Combine(AppPaths.DataDirectory, "app.log");

    public static void Info(string message)
    {
        Write("INFO", message);
    }

    public static void Error(Exception exception, string context)
    {
        Write("ERROR", $"{context}{Environment.NewLine}{exception}");
    }

    private static void Write(string level, string message)
    {
        try
        {
            Directory.CreateDirectory(DataDirectory);
            lock (Sync)
            {
                File.AppendAllText(LogPath, $"[{DateTimeOffset.Now:O}] [{level}] {message}{Environment.NewLine}", Encoding.UTF8);
            }
        }
        catch
        {
            // Logging must never break forensic collection.
        }
    }
}
