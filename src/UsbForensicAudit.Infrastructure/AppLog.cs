using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace UsbForensicAudit;

public static class AppLog
{
    private const int ProcessUserShadowStackPolicy = 15;

    /// <summary>Порог ротации. Журнал пишется подробно, но не должен расти без предела.</summary>
    private const long MaxLogBytes = 8L * 1024 * 1024;

    private static readonly object Sync = new();
    private static readonly DateTime ProcessStart = ResolveProcessStart();

    private static long _writtenBytes = -1;

    public static string DataDirectory => AppPaths.DataDirectory;
    public static string LogPath { get; } = Path.Combine(AppPaths.DataDirectory, "app.log");

    /// <summary>Предыдущий журнал после ротации.</summary>
    public static string PreviousLogPath => LogPath + ".1";

    private static string SessionMarkerPath => Path.Combine(DataDirectory, "session.open");

    public static void Info(string message)
    {
        Write("INFO", message);
    }

    public static void Warn(string message)
    {
        Write("WARN", message);
    }

    /// <summary>Сообщение из журнала работы в окне — тот же текст, что видит оператор.</summary>
    public static void Ui(string message)
    {
        Write("UI", message);
    }

    /// <summary>Действие оператора: нажатие кнопки, смена вкладки, открытие окна.</summary>
    public static void Action(string message)
    {
        Write("ACTION", message);
    }

    public static void Error(Exception exception, string context)
    {
        Write("ERROR", $"{context}{Environment.NewLine}{exception}");
    }

    /// <summary>
    /// Открывает сеанс и сообщает, если предыдущий не был закрыт штатно. Маркер на диске —
    /// единственный способ узнать про снятие процесса или падение рантайма: в таких случаях
    /// приложение не успевает записать ничего само.
    /// </summary>
    public static void BeginSession()
    {
        try
        {
            Directory.CreateDirectory(DataDirectory);

            if (File.Exists(SessionMarkerPath))
            {
                var previous = File.ReadAllText(SessionMarkerPath).Trim();
                Warn($"Предыдущий сеанс (начат {previous}) не завершился штатно: процесс не дошёл до выхода. " +
                     "Смотрите конец журнала до этой строки и журнал Windows «Приложение».");
            }

            File.WriteAllText(SessionMarkerPath, DateTimeOffset.Now.ToString("O"));
        }
        catch
        {
            // Диагностика не должна мешать запуску.
        }
    }

    /// <summary>Закрывает сеанс и снимает маркер: следующий запуск не сочтёт его аварийным.</summary>
    public static void EndSession(string reason)
    {
        Write("INFO", $"Завершение работы: {reason}. Сеанс длился {(DateTime.Now - ProcessStart).TotalSeconds:F1} с.");

        try
        {
            File.Delete(SessionMarkerPath);
        }
        catch
        {
            // Маркер только для диагностики.
        }
    }

    /// <summary>
    /// Отметка этапа запуска. Время отсчитывается от старта процесса, а не от первой
    /// записи, поэтому в него попадает распаковка single-file бандла во временную папку:
    /// если уже первый этап приходит с большой задержкой, тормозит не код приложения.
    /// Последний этап в журнале указывает, на чём именно повисло приложение.
    /// </summary>
    public static void Stage(string stage)
    {
        Write("STAGE", $"{(DateTime.Now - ProcessStart).TotalMilliseconds,8:F0} мс | {stage}");
    }

    /// <summary>
    /// Слепок окружения в начале журнала. Нужен для разбора запусков на чужих машинах,
    /// куда нет доступа: версия Windows, версия ntdll и состояние CET определяют,
    /// воспроизведётся ли dotnet/runtime#110920.
    /// </summary>
    public static void WriteEnvironment()
    {
        foreach (var line in DescribeEnvironment())
        {
            Write("ENV", line);
        }
    }

    private static IEnumerable<string> DescribeEnvironment()
    {
        yield return $"Версия сборки  : {ResolveInformationalVersion()}";
        yield return $"Исполняемый    : {Environment.ProcessPath}";
        yield return $"Размещение     : {AppPaths.LayoutDescription}";
        yield return $"Журнал         : {LogPath}";
        yield return $"Рантайм        : {RuntimeInformation.FrameworkDescription} ({RuntimeInformation.ProcessArchitecture})";
        yield return $"CET в процессе : {DescribeShadowStack()}";
        yield return $"Windows        : {DescribeWindows()}";
        yield return $"ntdll.dll      : {DescribeNtdll()}";
        yield return $"Процессор      : {DescribeProcessor()} ({Environment.ProcessorCount} лог. ядер)";
        yield return $"Администратор  : {AdminHelper.IsAdministrator()}";
        yield return $"Пользователь   : {Environment.UserDomainName}\\{Environment.UserName}";
        yield return $"Временная папка: {Path.GetTempPath()}";
    }

    private static DateTime ResolveProcessStart()
    {
        try
        {
            using var current = Process.GetCurrentProcess();
            return current.StartTime;
        }
        catch
        {
            return DateTime.Now;
        }
    }

    private static string ResolveInformationalVersion()
    {
        try
        {
            var assembly = Assembly.GetEntryAssembly() ?? typeof(AppLog).Assembly;
            return assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                   ?? assembly.GetName().Version?.ToString()
                   ?? "неизвестна";
        }
        catch
        {
            return "неизвестна";
        }
    }

    /// <summary>
    /// Включён ли для процесса теневой стек (CET). Сборки .NET 9+ помечают apphost
    /// флагом /CETCOMPAT, и на непропатченной Windows это роняет процесс до окна.
    /// Строка подтверждает, что запущена сборка с отключённым CET.
    /// </summary>
    private static string DescribeShadowStack()
    {
        try
        {
            if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, out var flags, sizeof(uint)))
            {
                return (flags & 1) != 0
                    ? "включён (теневой стек активен)"
                    : "выключен";
            }

            return $"не определено (код {Marshal.GetLastWin32Error()})";
        }
        catch
        {
            return "не определено";
        }
    }

    private static string DescribeWindows()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");

            if (key is null)
            {
                return Environment.OSVersion.VersionString;
            }

            var product = key.GetValue("ProductName") as string;
            var display = key.GetValue("DisplayVersion") as string;
            var build = key.GetValue("CurrentBuild") as string;
            var ubr = key.GetValue("UBR");
            return $"{product} {display}, сборка {build}.{ubr}";
        }
        catch
        {
            return Environment.OSVersion.VersionString;
        }
    }

    private static string DescribeNtdll()
    {
        try
        {
            var path = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
            var info = FileVersionInfo.GetVersionInfo(path);
            return $"{info.FileVersion} (исправление CET из KB5044273 нужно для .NET 9+)";
        }
        catch
        {
            return "не прочитана";
        }
    }

    private static string DescribeProcessor()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0");

            return key?.GetValue("ProcessorNameString") as string ?? "неизвестен";
        }
        catch
        {
            return "неизвестен";
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessMitigationPolicy(IntPtr process, int policy, out uint buffer, int length);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    private static void Write(string level, string message)
    {
        try
        {
            Directory.CreateDirectory(DataDirectory);
            var line = $"[{DateTimeOffset.Now:O}] [{level}] {message}{Environment.NewLine}";

            lock (Sync)
            {
                RotateIfNeeded(line.Length);
                File.AppendAllText(LogPath, line, Encoding.UTF8);
                _writtenBytes += line.Length;
            }
        }
        catch
        {
            // Логирование не должно ломать сбор форензик-данных.
        }
    }

    /// <summary>
    /// Размер отслеживается в памяти, а не запросом к файлу на каждой строке: подробный
    /// журнал пишется часто, и лишний вызов файловой системы заметен. Точности хватает —
    /// в файл дописывает только этот метод.
    /// </summary>
    private static void RotateIfNeeded(int pendingBytes)
    {
        if (_writtenBytes < 0)
        {
            var existing = new FileInfo(LogPath);
            _writtenBytes = existing.Exists ? existing.Length : 0;
        }

        if (_writtenBytes + pendingBytes < MaxLogBytes)
        {
            return;
        }

        try
        {
            File.Delete(PreviousLogPath);
            File.Move(LogPath, PreviousLogPath);
            _writtenBytes = 0;
        }
        catch
        {
            // Не удалось повернуть журнал — продолжаем писать в текущий.
            _writtenBytes = 0;
        }
    }
}
