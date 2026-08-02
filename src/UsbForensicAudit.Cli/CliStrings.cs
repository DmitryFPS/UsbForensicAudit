using System.Globalization;
using System.Resources;

namespace UsbForensicAudit;

/// <summary>
/// Доступ к локализованным строкам CLI. Базовая культура — русская
/// (Strings.resx), английский перевод собирается в satellite-сборку из
/// Strings.en.resx. Отсутствующий ключ возвращается как есть, чтобы опечатка
/// в ключе была видна в выводе, а не роняла процесс.
/// </summary>
internal static class CliStrings
{
    private static readonly ResourceManager Resources =
        new("UsbForensicAudit.Resources.Strings", typeof(CliStrings).Assembly);

    /// <summary>Строка по ключу для текущей UI-культуры.</summary>
    public static string Get(string key) =>
        Resources.GetString(key, CultureInfo.CurrentUICulture) ?? key;

    /// <summary>Форматированная строка по ключу для текущей UI-культуры.</summary>
    public static string Format(string key, params object?[] args) =>
        string.Format(CultureInfo.CurrentUICulture, Get(key), args);

    /// <summary>
    /// Применяет явно выбранный язык ко всем потокам процесса. Вызывается до
    /// разбора остальных аргументов, чтобы даже ошибки парсинга печатались на
    /// выбранном языке.
    /// </summary>
    public static void ApplyLanguage(string language)
    {
        var culture = CultureInfo.GetCultureInfo(language);
        CultureInfo.DefaultThreadCurrentUICulture = culture;
        CultureInfo.CurrentUICulture = culture;
    }
}
