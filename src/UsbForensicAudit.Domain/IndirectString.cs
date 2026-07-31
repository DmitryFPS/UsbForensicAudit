using System.Text;

namespace UsbForensicAudit;

/// <summary>
/// Имя устройства, которое Windows хранит не текстом, а ссылкой на строку
/// внутри файла драйвера: «@bth.inf,%microsoft%;Microsoft».
///
/// Показывать такую ссылку человеку нельзя: во вкладке она выглядит как мусор,
/// хотя нужное имя лежит в ней же — после точки с запятой стоит запасной текст,
/// и на русской Windows он уже переведён. Ссылка бывает с подстановкой: имя
/// сопряжённого телефона Windows дописывает отдельной строкой в скобках, из-за
/// чего одно имя занимало в таблице две строки.
///
/// Разбирается только показ. Исходное значение остаётся в записи, в базе и в
/// журнале доказательств: сверять отчёт с реестром надо по тому, что в реестре
/// написано, а не по тому, что удобно читать.
/// </summary>
public static class IndirectString
{
    /// <summary>
    /// Читаемое имя из ссылки. Пустая строка означает, что запасного текста в
    /// ссылке нет и показывать нечего — выдумывать имя вместо Windows нельзя.
    /// </summary>
    public static string Resolve(string? value)
    {
        var text = (value ?? "").Trim();
        if (text.Length == 0)
        {
            return "";
        }

        if (!text.StartsWith('@'))
        {
            return OneLine(text);
        }

        var lines = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length == 0)
        {
            return "";
        }

        var separator = lines[0].IndexOf(';');
        if (separator < 0)
        {
            return "";
        }

        var template = lines[0][(separator + 1)..];
        var arguments = lines.Skip(1).Select(ReadArgument).Where(x => x.Length > 0).ToArray();
        return OneLine(Unwrap(Substitute(template, arguments)));
    }

    /// <summary>Похоже ли значение на ссылку на строку в файле драйвера.</summary>
    public static bool LooksLikeReference(string? value)
    {
        var text = (value ?? "").TrimStart();
        return text.StartsWith('@') && text.Contains(',');
    }

    /// <summary>
    /// Продолжение ссылки: «;(Galaxy S9+ пользователь Дмитрий)». В скобках стоит
    /// то, что Windows подставляет вместо %1 — как правило, имя устройства,
    /// которое дал ему владелец. Терять его нельзя: в отчёте это единственное
    /// место, где видно, чей именно телефон был сопряжён.
    /// </summary>
    private static string ReadArgument(string line)
    {
        var text = line.TrimStart(';', ' ');
        return Unwrap(text).Trim();
    }

    private static string Substitute(string template, string[] arguments)
    {
        var text = template;
        for (var index = arguments.Length; index >= 1; index--)
        {
            text = text.Replace($"%{index}", arguments[index - 1], StringComparison.Ordinal);
        }

        // Оставшиеся места подстановки Windows заполнить нечем, и «%1» в имени
        // читается как ошибка программы. Знак конца строки «%0» из файлов
        // описания драйверов человеку не нужен вовсе.
        for (var index = 9; index >= 0; index--)
        {
            text = text.Replace($"%{index}", "", StringComparison.Ordinal);
        }

        return text;
    }

    /// <summary>Снимает скобки, в которые Windows заключает целое имя.</summary>
    private static string Unwrap(string value)
    {
        var text = value.Trim();
        if (text.Length < 2 || text[0] != '(' || text[^1] != ')')
        {
            return text;
        }

        var inner = text[1..^1];
        return inner.Contains(')') || inner.Contains('(') ? text : inner.Trim();
    }

    /// <summary>
    /// Одна строка без сдвоенных пробелов. В таблице у строки одна высота, и
    /// перевод строки внутри имени рвёт её надвое.
    /// </summary>
    private static string OneLine(string value)
    {
        var builder = new StringBuilder(value.Length);
        var previousSpace = false;
        foreach (var ch in value)
        {
            var isSpace = char.IsWhiteSpace(ch);
            if (isSpace && (previousSpace || builder.Length == 0))
            {
                continue;
            }

            builder.Append(isSpace ? ' ' : ch);
            previousSpace = isSpace;
        }

        return builder.ToString().TrimEnd();
    }
}
