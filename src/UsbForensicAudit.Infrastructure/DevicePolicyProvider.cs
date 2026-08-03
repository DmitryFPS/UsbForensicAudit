using System.IO;

namespace UsbForensicAudit;

/// <summary>
/// Загружает политику допустимых устройств из файла device-policy.json рядом с
/// программой (сначала каталог exe, затем каталог данных). Отсутствие файла —
/// не ошибка: политика просто не задана. Повреждённый файл логируется и не
/// прерывает аудит.
/// </summary>
public static class DevicePolicyProvider
{
    public static DevicePolicy LoadDefault()
    {
        foreach (var directory in new[] { AppPaths.ExeDirectory, AppPaths.DataDirectory })
        {
            if (string.IsNullOrWhiteSpace(directory))
            {
                continue;
            }

            var path = Path.Combine(directory, DevicePolicyEvaluator.DefaultFileName);
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                return DevicePolicyEvaluator.Parse(File.ReadAllText(path));
            }
            catch (Exception exception)
            {
                AppLog.Error(exception, $"Не удалось прочитать политику устройств: {path}");
                return DevicePolicy.None;
            }
        }

        return DevicePolicy.None;
    }
}
