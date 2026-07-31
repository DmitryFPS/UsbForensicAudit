using System.IO;
using Microsoft.Data.Sqlite;

namespace UsbForensicAudit;

/// <summary>Найденная база истории одного браузера и одного его профиля.</summary>
internal sealed record BrowserProfile(string Title, string DatabasePath, bool IsFirefox);

/// <summary>
/// Где браузеры держат историю.
///
/// Браузеров много, а история у всех, кроме Firefox, лежит в одинаковых базах:
/// различаются только папки. Профилей внутри одного браузера бывает несколько —
/// «Default», «Profile 1» и так далее, — и каждый ведёт свою историю, поэтому
/// проверять надо все.
/// </summary>
internal static class BrowserProfiles
{
    private static readonly (string Title, string Relative)[] ChromiumFamily =
    [
        ("Microsoft Edge", @"AppData\Local\Microsoft\Edge\User Data"),
        ("Google Chrome", @"AppData\Local\Google\Chrome\User Data"),
        ("Яндекс Браузер", @"AppData\Local\Yandex\YandexBrowser\User Data"),
        ("Brave", @"AppData\Local\BraveSoftware\Brave-Browser\User Data"),
        ("Vivaldi", @"AppData\Local\Vivaldi\User Data"),
        ("Chromium", @"AppData\Local\Chromium\User Data"),
        ("Opera", @"AppData\Roaming\Opera Software\Opera Stable"),
        ("Opera GX", @"AppData\Roaming\Opera Software\Opera GX Stable")
    ];

    private static readonly (string Title, string Relative)[] FirefoxFamily =
    [
        ("Firefox", @"AppData\Roaming\Mozilla\Firefox\Profiles"),
        ("Waterfox", @"AppData\Roaming\Waterfox\Profiles")
    ];

    internal static List<BrowserProfile> Find(string profilePath)
    {
        var result = new List<BrowserProfile>();

        foreach (var (title, relative) in ChromiumFamily)
        {
            var root = Path.Combine(profilePath, relative);
            if (!Directory.Exists(root))
            {
                continue;
            }

            // У Opera история лежит прямо в папке браузера, у остальных — в папках
            // профилей внутри неё.
            AddIfExists(result, title, Path.Combine(root, "History"), false);
            foreach (var directory in SafeDirectories(root))
            {
                AddIfExists(result, $"{title}, профиль «{Path.GetFileName(directory)}»",
                    Path.Combine(directory, "History"), false);
            }
        }

        foreach (var (title, relative) in FirefoxFamily)
        {
            var root = Path.Combine(profilePath, relative);
            foreach (var directory in SafeDirectories(root))
            {
                AddIfExists(result, $"{title}, профиль «{Path.GetFileName(directory)}»",
                    Path.Combine(directory, "places.sqlite"), true);
            }
        }

        return result;
    }

    private static void AddIfExists(List<BrowserProfile> result, string title, string path, bool isFirefox)
    {
        if (File.Exists(path))
        {
            result.Add(new BrowserProfile(title, path, isFirefox));
        }
    }

    private static IEnumerable<string> SafeDirectories(string root)
    {
        if (!Directory.Exists(root))
        {
            return [];
        }

        try
        {
            return Directory.EnumerateDirectories(root).Take(64).ToList();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}

/// <summary>
/// Копия базы во временной папке.
///
/// Браузер держит свою историю открытой, и читать её на месте нельзя: часть
/// записей лежит в незаписанном журнале, а само чтение меняет файл. Поэтому база
/// копируется вместе с журналами и открывается только для чтения — исходный
/// артефакт остаётся неприкосновенным.
/// </summary>
internal sealed class TemporaryDatabaseCopy : IDisposable
{
    private readonly string _directory;

    internal TemporaryDatabaseCopy(string source)
    {
        _directory = Path.Combine(Path.GetTempPath(),
            "UsbForensicAudit-history-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);

        Path_ = Path.Combine(_directory, Path.GetFileName(source));
        File.Copy(source, Path_, true);

        // Незаписанный журнал хранит последние по времени страницы: без него история
        // обрывается на несколько часов раньше, чем есть на самом деле.
        foreach (var suffix in new[] { "-wal", "-shm", "-journal" })
        {
            var extra = source + suffix;
            if (File.Exists(extra))
            {
                TryCopy(extra, Path_ + suffix);
            }
        }
    }

    private string Path_ { get; }

    internal SqliteConnection Open()
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path_,
            Mode = SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private
        }.ToString());

        connection.Open();
        return connection;
    }

    public void Dispose()
    {
        try
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(_directory, true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Временная копия остаётся до перезагрузки: помешать проверке это не может.
        }
    }

    private static void TryCopy(string source, string target)
    {
        try
        {
            File.Copy(source, target, true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Журнал бывает занят браузером целиком. История прочитается без него.
        }
    }
}
