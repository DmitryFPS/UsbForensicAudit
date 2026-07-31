using Microsoft.Win32;

namespace UsbForensicAudit;

/// <summary>
/// Соответствие «сеть из журнала — сеть из реестра».
///
/// В событии подключения к сети Windows называет её имя и GUID профиля, но вид
/// связи в событии указан ненадёжно: поле Type у беспроводной сети приходит тем
/// же нулём, что и у проводной. Вид связи достоверно записан только в реестре, в
/// поле NameType того же профиля. Без этого сопоставления события легли бы
/// отдельной строкой «вид связи неизвестен» рядом с той же самой сетью из
/// реестра, и одна сеть выглядела бы двумя.
/// </summary>
internal sealed class NetworkProfileIndex
{
    private const string ProfilesPath =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles";

    private readonly Dictionary<string, string> _byGuid = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _byName = new(StringComparer.OrdinalIgnoreCase);

    public static NetworkProfileIndex Build()
    {
        var index = new NetworkProfileIndex();
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(ProfilesPath);
            if (root is null)
            {
                return index;
            }

            foreach (var guid in root.GetSubKeyNames())
            {
                using var key = root.OpenSubKey(guid);
                if (key is null)
                {
                    continue;
                }

                var nameType = key.GetValue("NameType") as int? ?? 0;
                var (kind, _) = NetworkListParsers.DescribeNameType(nameType);
                index._byGuid[Normalize(guid)] = kind;

                var name = key.GetValue("ProfileName") as string ?? "";
                if (name.Length > 0)
                {
                    index._byName[name] = kind;
                }
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Отсутствие списка сетей само по себе не ошибка сбора: события
            // останутся с неизвестным видом связи, и это будет видно в отчёте.
        }

        return index;
    }

    /// <summary>
    /// Вид связи по GUID профиля, а если такого профиля в реестре уже нет — по
    /// имени сети. Профиль могли удалить, а события о нём остались.
    /// </summary>
    public string ResolveKind(string? guid, string? name)
    {
        if (!string.IsNullOrWhiteSpace(guid) && _byGuid.TryGetValue(Normalize(guid), out var byGuid))
        {
            return byGuid;
        }

        if (!string.IsNullOrWhiteSpace(name) && _byName.TryGetValue(name.Trim(), out var byName))
        {
            return byName;
        }

        return NetworkConnectionKind.Unknown;
    }

    private static string Normalize(string guid) => guid.Trim().Trim('{', '}');
}
