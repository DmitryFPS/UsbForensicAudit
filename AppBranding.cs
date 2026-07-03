using System.IO;
using System.Reflection;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace UsbForensicAudit;

public static class AppBranding
{
    public static ImageSource? LoadLogo(int decodePixelWidth = 256)
    {
        var embedded = TryLoadEmbeddedManifest(decodePixelWidth);
        if (embedded is not null)
        {
            return embedded;
        }

        foreach (var path in GetCandidatePaths())
        {
            var source = TryLoadFromPath(path, decodePixelWidth);
            if (source is not null)
            {
                return source;
            }
        }

        return TryLoadPackResource(decodePixelWidth);
    }

    private static IEnumerable<string> GetCandidatePaths()
    {
        var baseDirectory = AppContext.BaseDirectory;
        yield return Path.Combine(baseDirectory, "Assets", "app.ico");
        yield return Path.Combine(baseDirectory, "Assets", "app-icon.png");

        var projectAssets = FindProjectAssetsDirectory();
        if (!string.IsNullOrWhiteSpace(projectAssets))
        {
            yield return Path.Combine(projectAssets, "app.ico");
            yield return Path.Combine(projectAssets, "app-icon.png");
        }
    }

    private static string? FindProjectAssetsDirectory()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; depth < 8 && current is not null; depth++)
        {
            var candidate = Path.Combine(current.FullName, "Assets");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            current = current.Parent;
        }

        return null;
    }

    private static ImageSource? TryLoadFromPath(string path, int decodePixelWidth)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            if (path.EndsWith(".ico", StringComparison.OrdinalIgnoreCase))
            {
                return LoadIconFile(path, decodePixelWidth);
            }

            return LoadBitmapFile(path, decodePixelWidth);
        }
        catch
        {
            return null;
        }
    }

    private static ImageSource? TryLoadPackResource(int decodePixelWidth)
    {
        foreach (var uri in new[]
                 {
                     "pack://application:,,,/Assets/app-icon.png",
                     "pack://application:,,,/Assets/app.ico",
                     "pack://application:,,,/app-icon.png"
                 })
        {
            try
            {
                var bitmap = new BitmapImage();
                bitmap.BeginInit();
                bitmap.UriSource = new Uri(uri, UriKind.Absolute);
                bitmap.CacheOption = BitmapCacheOption.OnLoad;
                bitmap.DecodePixelWidth = decodePixelWidth;
                bitmap.EndInit();
                bitmap.Freeze();
                return bitmap;
            }
            catch
            {
                // Пробуем следующий pack-URI.
            }
        }

        return TryLoadEmbeddedManifest(decodePixelWidth);
    }

    private static ImageSource? TryLoadEmbeddedManifest(int decodePixelWidth)
    {
        var assembly = Assembly.GetExecutingAssembly();
        foreach (var name in new[] { "UsbForensicAudit.Assets.app.ico", "UsbForensicAudit.Assets.app-icon.png" })
        {
            try
            {
                using var stream = assembly.GetManifestResourceStream(name);
                if (stream is null)
                {
                    continue;
                }

                if (name.EndsWith(".ico", StringComparison.OrdinalIgnoreCase))
                {
                    return LoadIconStream(stream, decodePixelWidth);
                }

                return LoadBitmapStream(stream, decodePixelWidth);
            }
            catch
            {
                // Пробуем следующий встроенный ресурс.
            }
        }

        foreach (var name in assembly.GetManifestResourceNames())
        {
            if (!name.Contains("app-icon", StringComparison.OrdinalIgnoreCase)
                && !name.EndsWith(".ico", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            try
            {
                using var stream = assembly.GetManifestResourceStream(name);
                if (stream is null)
                {
                    continue;
                }

                if (name.EndsWith(".ico", StringComparison.OrdinalIgnoreCase))
                {
                    return LoadIconStream(stream, decodePixelWidth);
                }

                return LoadBitmapStream(stream, decodePixelWidth);
            }
            catch
            {
                // Пробуем следующий встроенный ресурс.
            }
        }

        return null;
    }

    private static ImageSource LoadIconFile(string path, int decodePixelWidth)
    {
        using var stream = File.OpenRead(path);
        return LoadIconStream(stream, decodePixelWidth);
    }

    private static ImageSource LoadIconStream(Stream stream, int decodePixelWidth)
    {
        using var buffer = CopyToMemoryStream(stream);
        var decoder = new IconBitmapDecoder(buffer, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
        var frame = decoder.Frames
            .OrderByDescending(f => f.PixelWidth)
            .FirstOrDefault(f => f.PixelWidth <= decodePixelWidth)
            ?? decoder.Frames.OrderByDescending(f => f.PixelWidth).First();

        if (frame.PixelWidth > decodePixelWidth)
        {
            var scaled = new TransformedBitmap(frame, new ScaleTransform(
                decodePixelWidth / (double)frame.PixelWidth,
                decodePixelWidth / (double)frame.PixelWidth));
            scaled.Freeze();
            return scaled;
        }

        frame.Freeze();
        return frame;
    }

    private static ImageSource LoadBitmapFile(string path, int decodePixelWidth)
    {
        using var stream = File.OpenRead(path);
        return LoadBitmapStream(stream, decodePixelWidth);
    }

    private static ImageSource LoadBitmapStream(Stream stream, int decodePixelWidth)
    {
        using var buffer = CopyToMemoryStream(stream);
        var bitmap = new BitmapImage();
        bitmap.BeginInit();
        bitmap.StreamSource = buffer;
        bitmap.CacheOption = BitmapCacheOption.OnLoad;
        bitmap.DecodePixelWidth = decodePixelWidth;
        bitmap.EndInit();
        bitmap.Freeze();
        return bitmap;
    }

    private static MemoryStream CopyToMemoryStream(Stream stream)
    {
        var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        buffer.Position = 0;
        return buffer;
    }
}
