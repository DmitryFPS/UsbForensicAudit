using System.IO;

namespace UsbForensicAudit;

/// <summary>
/// Загружает карточку дела из case.json рядом с программой (каталог exe, затем
/// каталог данных). Отсутствие файла — не ошибка; повреждённый логируется.
/// </summary>
public static class CaseMetadataProvider
{
    public static CaseMetadata LoadDefault()
    {
        foreach (var directory in new[] { AppPaths.ExeDirectory, AppPaths.DataDirectory })
        {
            if (string.IsNullOrWhiteSpace(directory))
            {
                continue;
            }

            var path = Path.Combine(directory, CaseMetadataReader.DefaultFileName);
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                return CaseMetadataReader.Parse(File.ReadAllText(path));
            }
            catch (Exception exception)
            {
                AppLog.Error(exception, $"Не удалось прочитать карточку дела: {path}");
                return CaseMetadata.None;
            }
        }

        return CaseMetadata.None;
    }
}
