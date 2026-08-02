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

    /// <summary>Показать справку и выйти.</summary>
    public bool ShowHelp { get; private set; }

    /// <summary>Ошибка разбора аргументов; null, когда разбор успешен.</summary>
    public string? Error { get; private set; }

    public static readonly IReadOnlyList<string> KnownFormats =
        ["html", "pdf", "brief-pdf", "analyst-pdf", "excel", "brief-excel", "analyst-excel"];

    public static CliOptions Parse(string[] args)
    {
        var options = new CliOptions();

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--help" or "-h" or "/?":
                    options.ShowHelp = true;
                    return options;

                case "--quiet" or "-q":
                    options.Quiet = true;
                    break;

                case "--list-sessions":
                    options.ListSessions = true;
                    break;

                case "--diff":
                    if (!TryTakeValue(args, ref i, out var baseline) ||
                        !TryTakeValue(args, ref i, out var target))
                    {
                        options.Error = "После --diff ожидаются два идентификатора сессий: базовая и целевая.";
                        return options;
                    }

                    options.DiffBaseline = baseline;
                    options.DiffTarget = target;
                    break;

                case "--json":
                    if (!TryTakeValue(args, ref i, out var jsonPath))
                    {
                        options.Error = "После --json ожидается путь к файлу.";
                        return options;
                    }

                    options.JsonPath = jsonPath;
                    break;

                case "--reports":
                    if (!TryTakeValue(args, ref i, out var reportDirectory))
                    {
                        options.Error = "После --reports ожидается путь к каталогу.";
                        return options;
                    }

                    options.ReportDirectory = reportDirectory;
                    break;

                case "--formats":
                    if (!TryTakeValue(args, ref i, out var formatsRaw))
                    {
                        options.Error = "После --formats ожидается список форматов через запятую.";
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
                            $"Неизвестный формат отчёта: {unknown}. Допустимые: {string.Join(", ", KnownFormats)}.";
                        return options;
                    }

                    options.ReportFormats = formats;
                    break;

                default:
                    options.Error = $"Неизвестный аргумент: {args[i]}. Запустите с --help для справки.";
                    return options;
            }
        }

        if (options.ReportFormats.Count > 0 && options.ReportDirectory is null)
        {
            options.Error = "Флаг --formats требует указания каталога отчётов через --reports.";
        }

        if ((options.ListSessions || options.DiffBaseline is not null) &&
            (options.ReportDirectory is not null || options.ReportFormats.Count > 0))
        {
            // Работа с уже сохранёнными сессиями и новое сканирование — разные
            // режимы: смешение флагов почти всегда означает опечатку в скрипте.
            options.Error = "--list-sessions и --diff несовместимы с --reports/--formats.";
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
