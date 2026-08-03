using System.IO;
using QuestPDF.Drawing;
using QuestPDF.Infrastructure;

namespace UsbForensicAudit;

public static class PdfFontHelper
{
    public const string DefaultFamily = "Segoe UI";

    private static readonly object RegistrationSync = new();
    private static bool _registered;

    public static void EnsureRegistered()
    {
        lock (RegistrationSync)
        {
            if (_registered)
            {
                return;
            }

            QuestPDF.Settings.License = LicenseType.Community;

            var registeredCount = 0;
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
                if (RegisterFontFile(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Fonts", fileName)))
                {
                    registeredCount++;
                }
            }

            if (registeredCount == 0)
            {
                // Урезанная установка Windows (Server Core и т.п.): PDF отрисуется
                // fallback-шрифтом QuestPDF и может потерять кириллицу.
                AppLog.Info(
                    "PdfFontHelper: не зарегистрирован ни один системный шрифт "
                    + $"({DefaultFamily}/Arial/Calibri) — кириллица в PDF-отчётах может не отображаться.");
            }

            _registered = true;
        }
    }

    private static bool RegisterFontFile(string path)
    {
        if (!File.Exists(path))
        {
            return false;
        }

        try
        {
            var bytes = File.ReadAllBytes(path);
            using var stream = new MemoryStream(bytes);
            FontManager.RegisterFont(stream);
            return true;
        }
        catch (Exception exception)
        {
            // Нечитаемый или повреждённый файл шрифта не должен срывать генерацию PDF,
            // но и молчать о нём нельзя — деградация видна только по логу.
            AppLog.Error(exception, $"PdfFontHelper: не удалось зарегистрировать шрифт {path}");
            return false;
        }
    }
}
