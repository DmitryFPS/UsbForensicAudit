using System.Text;
using UsbForensicAudit;

// Сборка встроенной базы префиксов MAC из файла manuf проекта Wireshark.
//
// База нужна, чтобы назвать изготовителя устройства, найденного в сети. Она
// собирается отдельной утилитой, а не скачивается программой на ходу: аудит
// обязан работать без интернета, а результат — не зависеть от того, что
// сегодня отвечает чужой сервер. Заодно видно, из какого именно файла и когда
// база собрана: это записано в её заголовке.
//
// Файл manuf: https://www.wireshark.org/download/automated/data/manuf

var repoRoot = LocateRepoRoot();
var sourcePath = args.Length > 0 ? args[0] : Path.Combine(repoRoot, "tools", "manuf.download");
var targetPath = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "Assets", "MacVendors.txt");

if (!File.Exists(sourcePath))
{
    Console.Error.WriteLine($"Source file not found: {sourcePath}");
    Console.Error.WriteLine("Download from https://www.wireshark.org/download/automated/data/manuf first.");
    return 1;
}

var entries = new SortedDictionary<string, string>(StringComparer.Ordinal);
var skipped = 0;

foreach (var line in File.ReadLines(sourcePath, Encoding.UTF8))
{
    var text = line.Trim();
    if (text.Length == 0 || text[0] == '#')
    {
        continue;
    }

    var columns = text.Split('\t', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (columns.Length < 2)
    {
        skipped++;
        continue;
    }

    var prefix = ReadPrefix(columns[0]);
    if (prefix.Length == 0)
    {
        skipped++;
        continue;
    }

    // Третий столбец — полное название изготовителя, второй — сокращение для
    // узких таблиц. Человеку нужнее полное: «TP-LINK TECHNOLOGIES CO.,LTD.»
    // понятно и без словаря, а «TpLink» надо разгадывать.
    var name = Clean(columns.Length >= 3 ? columns[2] : columns[1]);
    if (name.Length == 0)
    {
        skipped++;
        continue;
    }

    entries.TryAdd(prefix, name);
}

Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
await using (var writer = new StreamWriter(targetPath, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
{
    writer.WriteLine("# Префиксы аппаратных адресов (MAC) и их изготовители.");
    writer.WriteLine("# Источник: файл manuf проекта Wireshark, собранный из реестров IEEE MA-L, MA-M и MA-S.");
    writer.WriteLine($"# Собрано {DateTimeOffset.UtcNow:yyyy-MM-dd} утилитой tools/BuildMacVendorDatabase.");
    writer.WriteLine("# Формат строки: префикс/длина в битах <TAB> изготовитель.");
    writer.WriteLine();

    foreach (var entry in entries)
    {
        writer.WriteLine($"{entry.Key}/{entry.Key.Length * 4}\t{entry.Value}");
    }
}

Console.WriteLine($"MAC vendor database written to: {targetPath}");
Console.WriteLine($"Prefixes: {entries.Count:N0}, skipped lines: {skipped:N0}");
Console.WriteLine($"File size: {new FileInfo(targetPath).Length:N0} bytes");

using (var reader = new StreamReader(targetPath))
{
    Console.WriteLine($"Parsed back: {MacVendorCatalog.Parse(reader).Count:N0} prefixes");
}

return 0;

/// <summary>
/// Префикс из записи manuf: «00:00:0C» или «28:6F:B9:10:00:00/28». Длина
/// блока — то, сколько бит адреса закреплено за изготовителем; без неё блок
/// в 28 бит нельзя отличить от целого блока в 24.
/// </summary>
static string ReadPrefix(string value)
{
    var slash = value.IndexOf('/');
    var bits = 24;
    var head = value;
    if (slash >= 0)
    {
        head = value[..slash];
        if (!int.TryParse(value[(slash + 1)..], out bits))
        {
            return "";
        }
    }

    if (bits is not (24 or 28 or 36))
    {
        return "";
    }

    var digits = new StringBuilder(12);
    foreach (var ch in head)
    {
        if (Uri.IsHexDigit(ch))
        {
            digits.Append(char.ToUpperInvariant(ch));
        }
    }

    var length = bits / 4;
    return digits.Length >= length ? digits.ToString(0, length) : "";
}

static string Clean(string value)
{
    var text = value.Replace('\t', ' ').Trim();
    return text.Length <= 64 ? text : text[..64].TrimEnd();
}

static string LocateRepoRoot()
{
    var current = new DirectoryInfo(AppContext.BaseDirectory);
    for (var depth = 0; depth < 10 && current is not null; depth++)
    {
        if (File.Exists(Path.Combine(current.FullName, "UsbForensicAudit.csproj")))
        {
            return current.FullName;
        }

        current = current.Parent;
    }

    throw new InvalidOperationException("Could not locate UsbForensicAudit repository root.");
}
