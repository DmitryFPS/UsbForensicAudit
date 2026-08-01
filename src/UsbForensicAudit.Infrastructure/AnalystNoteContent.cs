namespace UsbForensicAudit;

/// <summary>
/// Общая подготовка данных для аналитической записки — одна на PDF и Excel,
/// чтобы обе формы записки рассказывали одно и то же слово в слово.
/// </summary>
internal static class AnalystNoteContent
{
    /// <summary>Событие общей хронологии.</summary>
    /// <param name="At">Момент события.</param>
    /// <param name="Text">Описание события одной строкой.</param>
    /// <param name="IsOlderThanOsInstall">
    /// Штамп старше установки Windows. Такое бывает и без противоречия:
    /// Shimcache хранит время изменения файла, а не запуска, а записи
    /// Jump Lists несут встроенные штампы самого файла. Но читателю записки
    /// об этом надо сказать, иначе год вроде 2021 выглядит ошибкой.
    /// </param>
    public readonly record struct ChronologyEvent(DateTimeOffset At, string Text, bool IsOlderThanOsInstall);

    /// <summary>Пояснение, которое печатается рядом с событием старше установки ОС.</summary>
    public const string PreInstallCaveat =
        "штамп из артефакта старше установки ОС: это время изменения файла-источника, а не момент действия";

    /// <summary>
    /// Общая лента событий: установка ОС, подключения устройств, сетевые
    /// события, действия с файлами и признаки очистки — по возрастанию времени.
    /// </summary>
    public static List<ChronologyEvent> BuildChronology(ForensicReportContext ctx)
    {
        var events = new List<(DateTimeOffset At, string Text)>();
        var result = ctx.Result;

        if (result.OsInstalledAtUtc is { } installed)
        {
            events.Add((installed, "Установка Windows."));
        }

        foreach (var device in ctx.ListedDevices)
        {
            if (device.FirstConnectedUtc is { } first)
            {
                events.Add((first, $"Устройство: {device.ModelText}, первое подключение."));
            }

            if (device.LastSeenUtc is { } last && last != device.FirstConnectedUtc)
            {
                events.Add((last, $"Устройство: {device.ModelText}, последняя активность."));
            }
        }

        foreach (var connection in ctx.NetworkConnections)
        {
            var label = connection.NameText.Length > 0 ? connection.NameText : connection.AddressText;
            if (connection.FirstSeenUtc is { } first)
            {
                events.Add((first, $"{connection.KindText}: {label}, первое событие."));
            }

            foreach (var session in connection.Sessions)
            {
                if (session.StartedUtc is { } started)
                {
                    var outcome = session.OutcomeText.Length > 0 ? $" {session.OutcomeText}" : "";
                    events.Add((started, $"{connection.KindText}: {label}.{outcome}"));
                }
            }
        }

        foreach (var (device, history) in ctx.DevicesWithActivity())
        {
            foreach (var entry in history.Entries)
            {
                events.Add((entry.TimestampUtc, $"{device.ModelText}: {entry.KindText} — {entry.PathText}."));
            }
        }

        foreach (var finding in ctx.CleanupFindings)
        {
            events.Add((finding.TimestampUtc, $"Признак очистки: {finding.Finding}"));
        }

        return events
            .Where(x => x.At > DateTimeOffset.MinValue)
            .OrderBy(x => x.At)
            .Select(x => new ChronologyEvent(x.At, x.Text, IsOlderThanOsInstall(ctx, x.At)))
            .ToList();
    }

    /// <summary>
    /// Штамп старше установки Windows — значит, дата пришла из артефакта,
    /// который хранит время изменения файла, а не время действия на машине.
    /// Само событие установки ОС такой пометки не получает.
    /// </summary>
    public static bool IsOlderThanOsInstall(ForensicReportContext ctx, DateTimeOffset at)
        => ctx.Result.OsInstalledAtUtc is { } installed && at < installed;

    /// <summary>Досье устройства в одну строку: тома, производитель, ContainerID, действия.</summary>
    public static string DeviceDetailLine(ForensicReportContext ctx, UsbDeviceRecord device)
    {
        var parts = new List<string>();
        if (device.DriveLetters.Length > 0)
        {
            parts.Add($"тома {device.DriveLetters}");
        }

        if (device.Manufacturer.Length > 0)
        {
            parts.Add($"производитель {device.Manufacturer}");
        }

        if (device.ContainerId.Length > 0)
        {
            parts.Add($"ContainerID {device.ContainerId}");
        }

        var activity = ctx.GetActivity(device);
        parts.Add(activity.IsEmpty
            ? "следов работы с файлами не найдено"
            : $"действий с файлами: {activity.Entries.Count}");

        return string.Join(", ", parts);
    }

    /// <summary>
    /// Предупреждения о совпадающих VID/PID у нескольких устройств —
    /// примета клонов или кастомной прошивки.
    /// </summary>
    public static IReadOnlyList<string> SharedVidPidWarnings(ForensicReportContext ctx)
    {
        return ctx.ListedDevices
            .Where(x => x.Vid.Length > 0 && x.Pid.Length > 0)
            .GroupBy(x => $"{x.Vid}:{x.Pid}", StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => $"Внимание: VID/PID {g.Key} совпадает у {g.Count()} устройств "
                         + $"({string.Join(", ", g.Select(x => x.ModelText))}) — возможен клон или кастомная прошивка.")
            .ToArray();
    }
}
