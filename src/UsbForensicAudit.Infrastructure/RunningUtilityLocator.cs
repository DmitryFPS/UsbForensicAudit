using System.Diagnostics;
using System.IO;

namespace UsbForensicAudit;

/// <summary>
/// Сопоставляет строку из отчёта сторонней утилиты с работающим процессом
/// этой утилиты. Вынесен из code-behind главного окна: правила сопоставления
/// имён и повторного поиска процесса — чистая логика, которую нужно
/// тестировать без WPF.
/// </summary>
public static class RunningUtilityLocator
{
    /// <summary>
    /// Ищет работающий процесс утилиты для строки отчёта. Кандидаты в порядке
    /// доверия: явно выбранная в списке, найденные сканером, последняя
    /// считанная. Каждый кандидат перепроверяется: процесс мог завершиться
    /// или перезапуститься с новым PID с момента обнаружения.
    /// </summary>
    public static RunningExternalUtility? Resolve(
        string rowUtilityName,
        RunningExternalUtility? selected,
        IReadOnlyList<RunningExternalUtility> known,
        RunningExternalUtility? lastCaptured)
    {
        if (selected is not null && NamesMatch(rowUtilityName, selected.DisplayName, selected.ProcessName))
        {
            var refreshed = TryRefresh(selected);
            if (refreshed is not null)
            {
                return refreshed;
            }
        }

        var match = known.FirstOrDefault(u => NamesMatch(rowUtilityName, u.DisplayName, u.ProcessName));
        if (match is not null)
        {
            var refreshed = TryRefresh(match);
            if (refreshed is not null)
            {
                return refreshed;
            }
        }

        if (lastCaptured is not null && NamesMatch(rowUtilityName, lastCaptured.DisplayName, lastCaptured.ProcessName))
        {
            var refreshed = TryRefresh(lastCaptured);
            if (refreshed is not null)
            {
                return refreshed;
            }
        }

        var rowDefinition = ExternalUtilityCatalog.MatchProcess(rowUtilityName)
                            ?? ExternalUtilityCatalog.Definitions.FirstOrDefault(def =>
                                rowUtilityName.Contains(def.DisplayName, StringComparison.OrdinalIgnoreCase)
                                || def.DisplayName.Contains(rowUtilityName, StringComparison.OrdinalIgnoreCase));

        if (rowDefinition is null)
        {
            return null;
        }

        return known
            .Where(u => string.Equals(u.UtilityId, rowDefinition.Id, StringComparison.OrdinalIgnoreCase))
            .Select(TryRefresh)
            .FirstOrDefault(u => u is not null);
    }

    /// <summary>
    /// Совпадает ли имя утилиты из строки отчёта с работающим процессом.
    /// Сравнение двустороннее и без учёта расширений: в отчёте пишут
    /// «USBDeview», а процесс называется «USBDeview.exe».
    /// </summary>
    public static bool NamesMatch(string rowUtilityName, string displayName, string processName)
    {
        var rowName = rowUtilityName.Trim();
        if (rowName.Length == 0)
        {
            return false;
        }

        if (rowName.Contains(displayName, StringComparison.OrdinalIgnoreCase)
            || displayName.Contains(rowName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var processBase = Path.GetFileNameWithoutExtension(processName);
        var rowBase = Path.GetFileNameWithoutExtension(rowName);
        return rowName.Contains(processBase, StringComparison.OrdinalIgnoreCase)
               || processBase.Contains(rowBase, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Перепроверяет, что процесс утилиты всё ещё жив, и обновляет его
    /// атрибуты. Если исходный PID умер — ищет перезапущенный процесс
    /// с тем же именем: пользователь мог закрыть и снова открыть утилиту.
    /// </summary>
    public static RunningExternalUtility? TryRefresh(RunningExternalUtility utility)
    {
        try
        {
            using var process = Process.GetProcessById(utility.ProcessId);
            if (process.HasExited)
            {
                return null;
            }

            process.Refresh();
            return Describe(utility, process);
        }
        catch
        {
            var processName = Path.GetFileNameWithoutExtension(utility.ProcessName);
            var live = Process.GetProcessesByName(processName).FirstOrDefault(x => !x.HasExited);
            if (live is null)
            {
                return null;
            }

            try
            {
                live.Refresh();
                return Describe(utility, live);
            }
            finally
            {
                live.Dispose();
            }
        }
    }

    /// <summary>
    /// Достаёт путь к папке сессии Procmon из текста ошибки. Раннер кладёт
    /// путь после маркера «Файлы:» — даже неудачная трассировка оставляет
    /// артефакты, которые нужно уметь открыть.
    /// </summary>
    public static string? ExtractProcmonSessionDirectory(string message)
    {
        const string marker = "Файлы:";
        var index = message.LastIndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return null;
        }

        return message[(index + marker.Length)..].Trim();
    }

    private static RunningExternalUtility Describe(RunningExternalUtility source, Process process) => new()
    {
        UtilityId = source.UtilityId,
        DisplayName = source.DisplayName,
        ProcessId = process.Id,
        ProcessName = process.ProcessName,
        MainWindowTitle = process.MainWindowTitle,
        HasMainWindow = process.MainWindowHandle != IntPtr.Zero
    };
}
