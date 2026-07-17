using System.Text;

namespace UsbForensicAudit;

public static class TextSanitizer
{
    private static readonly char[] ReplacementLikeChars = ['�', '\uFFFD'];
    private static readonly int[] ConsoleCodePages = [866, 1251, 65001, 1252];
    private static readonly string[] RestrictedTerms =
    [
        "Secret Net Studio",
        "Secret Net"
    ];
    private static bool _codePagesRegistered;

    public static string Clean(string value, int maxLength = 1000)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        var normalized = RedactRestrictedTerms(value).Normalize(NormalizationForm.FormC);
        var builder = new StringBuilder(normalized.Length);
        foreach (var ch in normalized)
        {
            if (ch == '\r' || ch == '\n' || ch == '\t')
            {
                builder.Append(' ');
                continue;
            }

            if (!char.IsControl(ch))
            {
                builder.Append(ch);
            }
        }

        var cleaned = CollapseSpaces(builder.ToString())
            .Replace("????", "", StringComparison.Ordinal)
            .Trim();

        cleaned = new string(cleaned.Where(ch => !ReplacementLikeChars.Contains(ch)).ToArray()).Trim();
        return cleaned.Length > maxLength ? cleaned[..maxLength] : cleaned;
    }

    public static string NormalizeDisplay(string value, int maxLength = 1000)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        var candidate = TryFixEncoding(value);
        candidate = KeepReadableText(candidate);
        candidate = Clean(candidate, maxLength);
        return IsReadableForDisplay(candidate) ? candidate : "";
    }

    public static string NormalizeConsoleOutput(byte[] bytes)
    {
        if (bytes.Length == 0)
        {
            return "";
        }

        EnsureCodePages();
        string? best = null;
        var bestScore = int.MinValue;

        foreach (var codePage in ConsoleCodePages)
        {
            try
            {
                var text = Encoding.GetEncoding(codePage).GetString(bytes).Trim();
                var score = ScoreReadableText(text);
                if (score > bestScore)
                {
                    bestScore = score;
                    best = text;
                }
            }
            catch
            {
                // Пробуем следующую кодовую страницу.
            }
        }

        return NormalizeDisplay(best ?? Encoding.UTF8.GetString(bytes), 4000);
    }

    public static bool IsReadableForDisplay(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || LooksLikeMojibake(value))
        {
            return false;
        }

        var allowed = 0;
        foreach (var ch in value)
        {
            if (IsAllowedDisplayChar(ch))
            {
                allowed++;
            }
        }

        if (allowed < Math.Max(4, (int)(value.Length * 0.82)))
        {
            return false;
        }

        return !HasSuspiciousMixedScript(value);
    }

    public static bool LooksLikeMojibake(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        var replacementCount = value.Count(ch => ReplacementLikeChars.Contains(ch) || ch == '?');
        if (replacementCount >= 2 && replacementCount >= value.Length / 6)
        {
            return true;
        }

        var printable = value.Count(ch => !char.IsControl(ch));
        var lettersOrDigits = value.Count(char.IsLetterOrDigit);
        if (printable > 20 && lettersOrDigits < printable / 8)
        {
            return true;
        }

        if (HasSuspiciousMixedScript(value))
        {
            return true;
        }

        var highBytes = value.Count(ch => ch >= '\u0080' && ch <= '\u00FF');
        var cyrillic = value.Count(ch => ch >= '\u0400' && ch <= '\u04FF');
        return highBytes > 6 && cyrillic == 0 && printable > 12;
    }

    public static string RedactRestrictedTerms(string value)
    {
        var result = value;
        foreach (var term in RestrictedTerms)
        {
            result = result.Replace(term, "корпоративная защита USB", StringComparison.OrdinalIgnoreCase);
        }

        return result;
    }

    private static string TryFixEncoding(string value)
    {
        if (!LooksLikeMojibake(value))
        {
            return value;
        }

        EnsureCodePages();

        var candidates = new List<string> { value };
        try
        {
            var latinBytes = Encoding.GetEncoding(1252).GetBytes(value);
            foreach (var codePage in new[] { 1251, 866, 65001 })
            {
                candidates.Add(Encoding.GetEncoding(codePage).GetString(latinBytes));
            }

            candidates.Add(Encoding.UTF8.GetString(latinBytes));
        }
        catch
        {
            // Игнорируем ошибки преобразования.
        }

        return candidates
            .Where(IsReadableForDisplay)
            .OrderByDescending(ScoreReadableText)
            .FirstOrDefault()
               ?? candidates.OrderByDescending(ScoreReadableText).FirstOrDefault()
               ?? value;
    }

    private static bool HasSuspiciousMixedScript(string value)
    {
        var sample = value;
        var slash = Math.Max(sample.LastIndexOf('\\'), sample.LastIndexOf('/'));
        if (slash >= 0 && slash < sample.Length - 1)
        {
            sample = sample[(slash + 1)..];
        }

        foreach (var token in sample.Split(
                     [' ', '.', '_', '-', ':', ';', ',', '(', ')', '[', ']', '{', '}'],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            var latinLetters = token.Count(ch => ch is >= 'A' and <= 'Z' or >= 'a' and <= 'z');
            var cyrillicLetters = token.Count(ch => ch >= '\u0400' && ch <= '\u04FF');
            if (latinLetters > 0 && cyrillicLetters > 0)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsAllowedDisplayChar(char ch)
    {
        return char.IsLetterOrDigit(ch)
               || char.IsWhiteSpace(ch)
               || ch is '\\' or '/' or ':' or '_' or '-' or '.' or '(' or ')' or '[' or ']' or '{' or '}' or '@' or '#' or ';' or ','
               || (ch >= '\u0400' && ch <= '\u04FF');
    }

    private static string KeepReadableText(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (char.IsControl(ch))
            {
                continue;
            }

            if (IsAllowedDisplayChar(ch))
            {
                builder.Append(ch);
            }
        }

        return CollapseSpaces(builder.ToString());
    }

    private static int ScoreReadableText(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return -1000;
        }

        var score = 0;
        score += value.Count(char.IsLetterOrDigit) * 3;
        score += value.Count(ch => ch is '\\' or '/' or ':' or '_' or '-') * 2;
        score -= value.Count(ch => ReplacementLikeChars.Contains(ch) || ch == '?') * 8;
        score -= value.Count(ch => char.IsControl(ch)) * 5;

        if (LooksLikeMojibake(value))
        {
            score -= 200;
        }

        return score;
    }

    private static void EnsureCodePages()
    {
        if (_codePagesRegistered)
        {
            return;
        }

        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        _codePagesRegistered = true;
    }

    private static string CollapseSpaces(string value)
    {
        var builder = new StringBuilder(value.Length);
        var previousSpace = false;
        foreach (var ch in value)
        {
            var isSpace = char.IsWhiteSpace(ch);
            if (isSpace && previousSpace)
            {
                continue;
            }

            builder.Append(isSpace ? ' ' : ch);
            previousSpace = isSpace;
        }

        return builder.ToString();
    }
}
