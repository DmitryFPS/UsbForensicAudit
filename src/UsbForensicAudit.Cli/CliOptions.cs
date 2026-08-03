namespace UsbForensicAudit;

/// <summary>
/// Разобранные аргументы командной строки headless-сканирования. Парсинг намеренно
/// без внешних библиотек: четыре флага не оправдывают новую зависимость в
/// forensic-инструменте с locked-режимом восстановления пакетов.
/// </summary>
public sealed class CliOptions
{
    /// <summary>Путь к JSON-файлу с полным результатом сканирования.</summary>
    public string? JsonPath { get; private set; }

    /// <summary>Каталог, куда складываются готовые отчёты.</summary>
    public string? ReportDirectory { get; private set; }

    /// <summary>Форматы отчётов из <see cref="KnownFormats"/>.</summary>
    public IReadOnlyList<string> ReportFormats { get; private set; } = [];

    /// <summary>Не печатать пошаговый прогресс сканирования.</summary>
    public bool Quiet { get; private set; }

    /// <summary>Показать сохранённые сессии и выйти, не сканируя.</summary>
    public bool ListSessions { get; private set; }

    /// <summary>Базовая (старая) сессия для сравнения.</summary>
    public string? DiffBaseline { get; private set; }

    /// <summary>Целевая (новая) сессия для сравнения.</summary>
    public string? DiffTarget { get; private set; }

    /// <summary>
    /// Корень чужой системы для офлайн-анализа: смонтированный образ диска
    /// или скопированный каталог Windows.
    /// </summary>
    public string? OfflineRoot { get; private set; }

    /// <summary>Проверить целостность доказательной базы и выйти, не сканируя.</summary>
    public bool Verify { get; private set; }

    /// <summary>
    /// Каталог с JSON-экспортами сканирований разных машин для сводного
    /// отчёта по флоту: какие носители появлялись на нескольких компьютерах.
    /// </summary>
    public string? FleetDirectory { get; private set; }

    /// <summary>Фоновый мониторинг USB без окна: алерты в консоль, журнал Windows, файл и вебхук.</summary>
    public bool Monitor { get; private set; }

    /// <summary>Показать справку и выйти.</summary>
    public bool ShowHelp { get; private set; }

    /// <summary>Ошибка разбора аргументов; null, когда разбор успешен.</summary>
    public string? Error { get; private set; }

    public static readonly IReadOnlyList<string> KnownFormats =
        ["html", "pdf", "brief-pdf", "analyst-pdf", "excel", "brief-excel", "analyst-excel"];

    public static CliOptions Parse(string[] args)
    {
        var options = new CliOptions();

        // Язык применяется до разбора остальных аргументов: даже сообщения об
        // ошибках парсинга должны печататься на явно выбранном языке.
        var languageIndex = Array.IndexOf(args, "--lang");
        if (languageIndex >= 0)
        {
            if (languageIndex + 1 >= args.Length ||
                args[languageIndex + 1] is not ("ru" or "en"))
            {
                options.Error = CliStrings.Get("ErrLangArg");
                return options;
            }

            CliStrings.ApplyLanguage(args[languageIndex + 1]);
        }

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--help" or "-h" or "/?":
                    options.ShowHelp = true;
                    return options;

                case "--lang":
                    i++; // Значение уже применено до цикла.
                    break;

                case "--quiet" or "-q":
                    options.Quiet = true;
                    break;

                case "--list-sessions":
                    options.ListSessions = true;
                    break;

                case "--verify":
                    options.Verify = true;
                    break;

                case "--diff":
                    if (!TryTakeValue(args, ref i, out var baseline) ||
                        !TryTakeValue(args, ref i, out var target))
                    {
                        options.Error = CliStrings.Get("ErrDiffArgs");
                        return options;
                    }

                    options.DiffBaseline = baseline;
                    options.DiffTarget = target;
                    break;

                case "--monitor":
                    options.Monitor = true;
                    break;

                case "--fleet":
                    if (!TryTakeValue(args, ref i, out var fleetDirectory))
                    {
                        options.Error = CliStrings.Get("ErrFleetArg");
                        return options;
                    }

                    options.FleetDirectory = fleetDirectory;
                    break;

                case "--offline":
                    if (!TryTakeValue(args, ref i, out var offlineRoot))
                    {
                        options.Error = CliStrings.Get("ErrOfflineArg");
                        return options;
                    }

                    options.OfflineRoot = offlineRoot;
                    break;

                case "--json":
                    if (!TryTakeValue(args, ref i, out var jsonPath))
                    {
                        options.Error = CliStrings.Get("ErrJsonArg");
                        return options;
                    }

                    options.JsonPath = jsonPath;
                    break;

                case "--reports":
                    if (!TryTakeValue(args, ref i, out var reportDirectory))
                    {
                        options.Error = CliStrings.Get("ErrReportsArg");
                        return options;
                    }

                    options.ReportDirectory = reportDirectory;
                    break;

                case "--formats":
                    if (!TryTakeValue(args, ref i, out var formatsRaw))
                    {
                        options.Error = CliStrings.Get("ErrFormatsArg");
                        return options;
                    }

                    var formats = formatsRaw
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Select(static f => f.ToLowerInvariant())
                        .Distinct()
                        .ToList();
                    var unknown = formats.FirstOrDefault(static f => !KnownFormats.Contains(f));
                    if (unknown is not null)
                    {
                        options.Error =
                            CliStrings.Format("ErrUnknownFormat", unknown, string.Join(", ", KnownFormats));
                        return options;
                    }

                    options.ReportFormats = formats;
                    break;

                default:
                    options.Error = CliStrings.Format("ErrUnknownArg", args[i]);
                    return options;
            }
        }

        if (options.ReportFormats.Count > 0 && options.ReportDirectory is null)
        {
            options.Error = CliStrings.Get("ErrFormatsWithoutReports");
        }

        if ((options.ListSessions || options.DiffBaseline is not null) &&
            (options.ReportDirectory is not null || options.ReportFormats.Count > 0))
        {
            // Работа с уже сохранёнными сессиями и новое сканирование — разные
            // режимы: смешение флагов почти всегда означает опечатку в скрипте.
            options.Error = CliStrings.Get("ErrListDiffMix");
        }

        if (options.OfflineRoot is not null &&
            (options.ListSessions || options.DiffBaseline is not null))
        {
            options.Error = CliStrings.Get("ErrOfflineMix");
        }

        if (options.Monitor &&
            (options.OfflineRoot is not null || options.DiffBaseline is not null ||
             options.ListSessions || options.Verify || options.FleetDirectory is not null ||
             options.JsonPath is not null || options.ReportDirectory is not null || options.ReportFormats.Count > 0))
        {
            // Мониторинг — резидентный режим: смешение с разовыми операциями
            // сделало бы непонятным, что именно выполняется.
            options.Error = CliStrings.Get("ErrMonitorMix");
        }

        if (options.FleetDirectory is not null &&
            (options.OfflineRoot is not null || options.DiffBaseline is not null ||
             options.ListSessions || options.Verify ||
             options.ReportDirectory is not null || options.ReportFormats.Count > 0))
        {
            // Флот читает готовые JSON-экспорты и ничего не сканирует: смешение
            // с другими режимами почти всегда означает опечатку в скрипте.
            options.Error = CliStrings.Get("ErrFleetMix");
        }

        if (options.Verify &&
            (options.OfflineRoot is not null || options.DiffBaseline is not null ||
             options.ListSessions || options.ReportDirectory is not null || options.ReportFormats.Count > 0))
        {
            // Верификация читает журнал и базу, ничего не записывая; смешение
            // с режимами записи скрыло бы, какое именно действие выполнилось.
            options.Error = CliStrings.Get("ErrVerifyMix");
        }

        if (options.ReportDirectory is not null && options.ReportFormats.Count == 0)
        {
            // Каталог задан, форматы нет — берём самый востребованный набор.
            options.ReportFormats = ["html", "pdf"];
        }

        return options;
    }

    private static bool TryTakeValue(string[] args, ref int index, out string value)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
        {
            value = "";
            return false;
        }

        index++;
        value = args[index];
        return true;
    }
}
