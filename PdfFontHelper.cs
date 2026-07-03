using System.IO;
using QuestPDF.Drawing;
using QuestPDF.Infrastructure;

namespace UsbForensicAudit;

public static class PdfFontHelper
{
    public const string DefaultFamily = "Segoe UI";

    private static bool _registered;

    public static void EnsureRegistered()
    {
        if (_registered)
        {
            return;
        }

        QuestPDF.Settings.License = LicenseType.Community;

        foreach (var fileName in new[]
                 {
                     "segoeui.ttf",
                     "segoeuib.ttf",
                     "segoeuii.ttf",
                     "segoeuisl.ttf",
                     "arial.ttf",
                     "arialbd.ttf",
                     "calibri.ttf",
                     "calibrib.ttf"
                 })
        {
            RegisterFontFile(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Fonts", fileName));
        }

        _registered = true;
    }

    private static void RegisterFontFile(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            var bytes = File.ReadAllBytes(path);
            using var stream = new MemoryStream(bytes);
            FontManager.RegisterFont(stream);
        }
        catch
        {
            // Игнорируем повторную регистрацию или нечитаемые файлы шрифтов.
        }
    }
}
