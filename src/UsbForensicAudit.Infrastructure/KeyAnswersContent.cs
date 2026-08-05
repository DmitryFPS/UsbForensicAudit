namespace UsbForensicAudit;

/// <summary>
/// Три главных ответа расследования — единый источник для всех форматов
/// отчёта (HTML, PDF, Excel). Правило «от частного к общему»: каждый отчёт
/// открывается этими ответами, а доказательства идут после. Логика вердиктов
/// собрана в одном месте, чтобы форматы не расходились между собой (однажды
/// HTML уже отвечал «признаков не найдено» при наличии переносов
/// с неопределённым направлением — дубль этой логики в PDF повторил бы баг).
/// </summary>
internal static class KeyAnswersContent
{
    /// <summary>Окраска ответа: спокойный, требует внимания, тревожный, нейтральный.</summary>
    internal enum Tone
    {
        Ok,
        Attention,
        Bad,
        Plain
    }

    /// <summary>Один ответ: вопрос, короткий вердикт, пояснение и окраска.</summary>
    internal readonly record struct Answer(string Question, string Verdict, string Note, Tone Tone);

    /// <summary>
    /// Приоритетная зацепка для блока «с чего начать»: текст и раздел,
    /// в котором лежат подробности. Каждый формат сам решает, как назвать
    /// место — «вкладка», «страница» или «лист».
    /// </summary>
    internal readonly record struct StartPoint(string Text, string SectionHint);

    public static IReadOnlyList<Answer> Build(ForensicReportContext ctx)
    {
        var answers = new List<Answer>(3);

        // Вопрос 1: что подключали.
        var externalDevices = ctx.ListedDevices.Where(x => x.IsExternalDevice).ToArray();
        var lastSeen = externalDevices
            .Select(x => x.LastSeenUtc)
            .Where(x => x is not null)
            .OrderByDescending(x => x)
            .FirstOrDefault();
        var devicesTone = ctx.PolicySummary.HasViolations
            ? Tone.Bad
            : externalDevices.Length > 0 ? Tone.Plain : Tone.Ok;
        var devicesVerdict = externalDevices.Length == 0
            ? "Следов внешних носителей не найдено"
            : $"Да — внешних устройств: {externalDevices.Length}";
        var devicesNote = externalDevices.Length == 0
            ? "Ни флешек, ни внешних дисков, ни телефонов среди следов нет. Отсутствие следов не доказывает отсутствие подключений."
            : (lastSeen is not null
                ? $"Последняя активность внешнего устройства: {DateDisplay.FormatMoscow(lastSeen.Value)}."
                : "Точное время последней активности определить не удалось.")
              + (ctx.PolicySummary.HasViolations
                  ? $" Нарушений политики устройств: {ctx.PolicySummary.Violations.Count}."
                  : string.Empty);
        answers.Add(new Answer("Подключали ли внешние носители?", devicesVerdict, devicesNote, devicesTone));

        // Вопрос 2: работали ли с файлами на носителях. Прежний вопрос
        // «уходили ли данные?» был нечестным: Windows фиксирует копирование
        // на флешку лишь при редком стечении условий (живой журнал NTFS,
        // совпадение имён, близкое время), и зелёное «признаков не найдено»
        // читалось как «данные не уходили». Открытия файлов, папок и запуски
        // программ с носителей артефакты фиксируют надёжно (LNK, Recent,
        // ShellBags, Shimcache) — об этом и спрашиваем. Признаки выноса,
        // когда они есть, по-прежнему эскалируют тон и попадают в пояснение.
        var withActivity = ctx.DevicesWithActivity().ToArray();
        var activityDevices = withActivity.Length;
        var actions = withActivity.Sum(x => x.History.Entries.Count);
        var lastAction = withActivity
            .SelectMany(x => x.History.Entries)
            .Select(x => x.TimestampUtc)
            .OrderByDescending(x => x)
            .Cast<DateTimeOffset?>()
            .FirstOrDefault();

        var exf = ctx.Exfiltration;
        var filesTone = exf.ConfirmedCount > 0
            ? Tone.Bad
            : exf.HasAnyIndication
                ? Tone.Attention
                : activityDevices > 0 ? Tone.Plain : Tone.Ok;
        var filesVerdict = activityDevices > 0
            ? $"Да — {actions} действ.(ий) на {activityDevices} устройствах"
            : "Следов работы с файлами не найдено";
        var filesNote = activityDevices > 0
            ? (lastAction is not null
                  ? $"Последнее действие: {DateDisplay.FormatMoscow(lastAction.Value)}. "
                  : string.Empty)
              + ExfiltrationClause(exf)
            : "Открытий файлов, папок и запусков программ с носителей среди артефактов нет. " + ExfiltrationClause(exf);
        answers.Add(new Answer("Работали ли с файлами на носителях?", filesVerdict, filesNote, filesTone));

        // Вопрос 3: чистили ли следы.
        var cleanupTone = ctx.HighRiskCount > 0
            ? Tone.Bad
            : ctx.SuspiciousCount > 0 || ctx.AttentionCount > 0 ? Tone.Attention : Tone.Ok;
        var cleanupVerdict = ctx.HighRiskCount > 0
            ? $"Да, вероятно — находок высокого риска: {ctx.HighRiskCount}"
            : ctx.SuspiciousCount > 0
                ? $"Возможно — подозрительных находок: {ctx.SuspiciousCount}"
                : ctx.AttentionCount > 0
                    ? $"Явной очистки нет, но есть {ctx.AttentionCount} наход(ок), требующих внимания"
                    : "Признаков очистки следов не найдено";
        answers.Add(new Answer("Чистили ли следы?", cleanupVerdict, ctx.CleanupVerdict(), cleanupTone));

        return answers;
    }

    /// <summary>
    /// Фраза о выносе данных внутри пояснения ко второму ответу. Когда
    /// признаков нет, ограничения метода названы прямо: молчание артефактов
    /// копирования ничего не доказывает, и подавать его зелёным вердиктом нельзя.
    /// </summary>
    private static string ExfiltrationClause(ExfiltrationSummary exf)
    {
        if (exf.ConfirmedCount > 0 || exf.HasAnyIndication)
        {
            return exf.Verdict();
        }

        return "Признаков копирования на носители нет, но Windows фиксирует копирование "
               + "лишь при редком стечении условий — отсутствие таких следов не доказывает, "
               + "что данные не уходили.";
    }

    /// <summary>
    /// Приоритетные зацепки: с чего начинать проверку. Пустой список означает,
    /// что явных зацепок нет и читать стоит хронологию и список устройств.
    /// </summary>
    public static IReadOnlyList<StartPoint> StartPoints(ForensicReportContext ctx)
    {
        var points = new List<StartPoint>();
        if (ctx.HighRiskCount > 0)
        {
            points.Add(new StartPoint(
                $"находки высокого риска ({ctx.HighRiskCount})",
                "признаки очистки следов"));
        }

        if (ctx.Exfiltration.ConfirmedCount > 0)
        {
            points.Add(new StartPoint(
                $"файлы с подтверждённым копированием на носитель ({ctx.Exfiltration.ConfirmedCount})",
                "вынос данных"));
        }

        if (ctx.PolicySummary.HasViolations)
        {
            points.Add(new StartPoint(
                $"нарушения политики устройств ({ctx.PolicySummary.Violations.Count})",
                "соответствие политике"));
        }

        return points;
    }
}
