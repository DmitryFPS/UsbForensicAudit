using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

internal sealed record PidlArtifact(
    IReadOnlyList<string> PathFragments,
    string BestPath,
    string VolumeGuid,
    bool HasPortableDeviceItem = false);

internal sealed record ShellBagArtifact(string Path, int? Slot, bool IsUsbRelevant, string RelevanceReason = "");
internal sealed record JumpListEntry(string AppId, string StreamName, ShellLinkInfo Link, DateTimeOffset? EntryTimestampUtc);
internal sealed record ShimcacheEntry(string Path, DateTimeOffset? LastModifiedUtc, bool ExecutionProven);
internal sealed record ShimcacheParseResult(bool Supported, string Layout, IReadOnlyList<ShimcacheEntry> Entries, string Warning);

internal static partial class ForensicArtifactParsers
{
    private const int MaxPidlItems = 128;
    private static readonly byte[] LinkClsid =
    [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    ];

    internal static IReadOnlyList<int> ParseMruListEx(object? value)
    {
        if (value is not byte[] bytes)
        {
            return [];
        }

        var result = new List<int>();
        for (var offset = 0; offset + 4 <= bytes.Length && result.Count < 4096; offset += 4)
        {
            var item = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset, 4));
            if (item == -1)
            {
                break;
            }
            if (item >= 0 && !result.Contains(item))
            {
                result.Add(item);
            }
        }
        return result;
    }

    internal static PidlArtifact ParsePidl(byte[]? bytes)
    {
        if (bytes is null || bytes.Length < 2)
        {
            return new PidlArtifact([], "", "");
        }

        var fragments = new List<string>();
        var itemNames = new List<string>();
        var hasPortableDeviceItem = false;
        var offset = 0;
        for (var count = 0; count < MaxPidlItems && offset + 2 <= bytes.Length; count++)
        {
            var size = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
            if (size == 0)
            {
                break;
            }
            if (size < 2 || offset + size > bytes.Length)
            {
                break;
            }

            var body = bytes.AsSpan(offset + 2, size - 2);
            var itemFragments = new List<string>();
            hasPortableDeviceItem |= ExtractShellItemNames(body, itemFragments);

            // Имена из блоков с подписью — то, что оболочка показывает человеку.
            // Всё, что найдено дальше простым поиском строк, годится только как
            // запасной вариант: там же лежат свойства элемента и GUID-ы.
            var preferred = itemFragments.Count;
            ExtractReadableStrings(body, itemFragments);
            fragments.AddRange(itemFragments);

            var name = ChooseItemName(itemFragments, preferred);
            if (name.Length > 0)
            {
                itemNames.Add(name);
            }

            offset += size;
        }

        if (fragments.Count == 0)
        {
            ExtractReadableStrings(bytes, fragments);
        }

        var unique = fragments
            .Select(CleanFragment)
            .Where(IsUsefulFragment)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(64)
            .ToArray();
        var volume = unique.Select(ExtractVolumeGuid).FirstOrDefault(x => x.Length > 0) ?? "";
        return new PidlArtifact(unique, BuildPath(itemNames, unique), volume, hasPortableDeviceItem);
    }

    /// <summary>
    /// Путь — это цепочка имён элементов оболочки, по одному имени на элемент.
    ///
    /// Прежде путь склеивался из всех найденных в элементе строк, и один узел
    /// BagMRU давал строку вида «Общий накопитель\10001,,48582488064}\структура\
    /// 107D5-A52A-4243...». Читалось это как перечень вложенных папок, которых
    /// никогда не существовало: на самом деле там имя папки и рядом свойства
    /// элемента с обрубками GUID-ов.
    /// </summary>
    private static string BuildPath(List<string> itemNames, string[] fragments)
    {
        if (itemNames.Count == 0)
        {
            // Готовый путь целиком в одной строке бывает в ярлыках и в списках диалогов.
            return fragments.FirstOrDefault(x => DrivePathRegex().IsMatch(x) || VolumePathRegex().IsMatch(x)) ?? "";
        }

        // «E:\» и «\\сервер\ресурс» уже несут разделитель. Первое имя берётся как
        // есть, а перед каждым следующим ставится ровно один разделитель.
        var path = new StringBuilder();
        foreach (var name in itemNames.Where(x => x.Length > 0))
        {
            if (path.Length == 0)
            {
                path.Append(name);
                continue;
            }

            if (path[^1] != '\\')
            {
                path.Append('\\');
            }

            path.Append(name.TrimStart('\\'));
        }

        return path.ToString();
    }

    /// <summary>
    /// Имя элемента — первое похожее на имя папки или файла. Именно первое, а не
    /// самое длинное: оболочка хранит отображаемое имя перед свойствами, и самой
    /// длинной строкой в элементе обычно оказывается путь устройства вида
    /// «\\?\usb#vid_2717&amp;pid_ff40#...», который человеку ничего не говорит.
    /// </summary>
    private static string ChooseItemName(List<string> fragments, int preferredCount)
    {
        var cleaned = fragments.Select(CleanFragment).ToArray();
        var fromNameBlocks = cleaned.Take(preferredCount).FirstOrDefault(IsPlausibleItemName);
        return fromNameBlocks ?? cleaned.Skip(preferredCount).FirstOrDefault(IsPlausibleItemName) ?? "";
    }

    /// <summary>
    /// Имена папок не содержат фигурных скобок и решёток, а свойства элементов
    /// оболочки и идентификаторы устройств состоят из них почти целиком. Ещё
    /// отбрасываются шестнадцатеричные наборы: это обрубки GUID-ов, прочитанные
    /// с чужого выравнивания.
    ///
    /// В отличие от отбора фрагментов, здесь требуется, чтобы имя состояло из
    /// знаков имени целиком, без единого исключения. Часть элементов хранит имя
    /// однобайтовой строкой, и тот же однобайтовый проход читает как текст любые
    /// двоичные поля: так в отчёт попадали «корневые папки» «1SPSsCå», «Yr?§D» и
    /// «Ñ». Одного чужого знака достаточно, чтобы отличить их от имени.
    /// </summary>
    private static bool IsPlausibleItemName(string value)
    {
        if (!IsUsefulFragment(value)
            || value.AsSpan().IndexOfAny('{', '}', '#') >= 0
            || !value.All(IsNameCharacter))
        {
            return false;
        }

        var meaningful = value.Where(char.IsLetterOrDigit).ToArray();
        return meaningful.Length < 8 || !meaningful.All(Uri.IsHexDigit);
    }

    internal static ShellBagArtifact ParseShellBagNode(
        byte[]? value, string parentPath, int? slot, string? systemDrive = null)
    {
        var pidl = ParsePidl(value);
        var fragment = pidl.BestPath;
        var path = string.IsNullOrWhiteSpace(parentPath)
            ? fragment
            : string.IsNullOrWhiteSpace(fragment) ? parentPath : $"{parentPath.TrimEnd('\\')}\\{fragment.TrimStart('\\')}";

        var reason = RelevanceReason(path, pidl, systemDrive);
        return new ShellBagArtifact(path, slot, reason.Length > 0, reason);
    }

    /// <summary>
    /// Прежний отбор оставлял узел, только если в тексте пути было слово USB, WPD,
    /// removable или GUID тома. Папка на флешке выглядит как обычный путь E:\Фото,
    /// а папка на телефоне — как имя устройства, и обе отбрасывались: в отчёте не
    /// было видно, куда пользователь заходил на съёмном носителе.
    ///
    /// Признак ищется по всем строкам элемента, а не только по пути. Путь теперь
    /// содержит имя, которое видит человек: у телефона это «POCO X3 NFC», и слова
    /// USB в нём нет — оно осталось в служебной строке «\\?\usb#vid_2717&amp;…».
    /// </summary>
    private static string RelevanceReason(string path, PidlArtifact pidl, string? systemDrive)
    {
        var text = $"{path} {pidl.VolumeGuid} {string.Join(' ', pidl.PathFragments)}";
        if (IsUsbOrVolumeMarker(text))
        {
            return "Явный признак USB, WPD или тома в элементе оболочки.";
        }

        if (pidl.HasPortableDeviceItem)
        {
            return "Элемент оболочки переносного устройства (MTP).";
        }

        var drive = NonSystemDriveLetter(path, systemDrive);
        return drive.Length > 0
            ? $"Путь на диске {drive}, отличном от системного."
            : "";
    }

    /// <summary>
    /// Буква диска, если путь начинается не с системного диска. Съёмный носитель
    /// всегда получает такую букву; второй внутренний диск тоже, поэтому запись
    /// остаётся косвенной и подтверждается сопоставлением томов.
    /// </summary>
    private static string NonSystemDriveLetter(string path, string? systemDrive)
    {
        var match = DriveLetterPrefixRegex().Match(path.TrimStart('\\', ' '));
        if (!match.Success)
        {
            return "";
        }

        var letter = match.Groups["drive"].Value.ToUpperInvariant();
        var system = (systemDrive ?? "").TrimEnd('\\', ':').ToUpperInvariant();
        if (system.Length == 0)
        {
            system = "C";
        }

        return letter.Equals(system, StringComparison.Ordinal) ? "" : $"{letter}:";
    }

    internal static bool IsUsbOrVolumeMarker(string value) =>
        value.Contains("USB", StringComparison.OrdinalIgnoreCase)
        || value.Contains("WPDBUSENUM", StringComparison.OrdinalIgnoreCase)
        || DeviceMarkerText.ContainsWord(value, "WPD")
        || value.Contains("removable", StringComparison.OrdinalIgnoreCase)
        || VolumePathRegex().IsMatch(value);

    internal static IReadOnlyList<JumpListEntry> ParseAutomaticJumpList(byte[] data, string appId)
    {
        if (!CompoundFile.TryReadStreams(data, out var streams))
        {
            return [];
        }

        var timestamps = streams.TryGetValue("DestList", out var destList)
            ? ParseDestListTimestamps(destList)
            : [];
        var result = new List<JumpListEntry>();
        foreach (var (name, stream) in streams)
        {
            if (name.Equals("DestList", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var link = ShellLinkParser.TryParse(stream, $"{appId}:{name}");
            if (link is not null)
            {
                timestamps.TryGetValue(name, out var timestamp);
                result.Add(new JumpListEntry(appId, name, link, timestamp));
            }
        }
        return result;
    }

    internal static IReadOnlyList<JumpListEntry> ParseCustomJumpList(byte[] data, string appId)
    {
        var result = new List<JumpListEntry>();
        for (var offset = 0; offset + 0x4C <= data.Length && result.Count < 2048; offset++)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4)) != 0x4C
                || !data.AsSpan(offset + 4, 16).SequenceEqual(LinkClsid))
            {
                continue;
            }

            var next = FindLinkHeader(data, offset + 0x4C);
            var length = (next < 0 ? data.Length : next) - offset;
            var link = ShellLinkParser.TryParse(data.AsSpan(offset, length).ToArray(), $"{appId}:custom:{offset:X}");
            if (link is not null)
            {
                result.Add(new JumpListEntry(appId, offset.ToString("X"), link, null));
                offset += Math.Max(0, length - 1);
            }
        }
        return result;
    }

    internal static ShimcacheParseResult ParseShimcache(byte[]? data)
    {
        if (data is null || data.Length < 16)
        {
            return new ShimcacheParseResult(false, "Unknown", [], "AppCompatCache value is empty or truncated.");
        }

        // Windows 10/11 entries are identified by the documented 10ts signature. Header
        // size varies by build, so entries are located structurally and bounds-checked.
        const uint signature10Ts = 0x73743031;
        var entries = new List<ShimcacheEntry>();
        for (var offset = 0; offset + 12 <= data.Length && entries.Count < 50_000;)
        {
            var found = IndexOfUInt32(data, signature10Ts, offset);
            if (found < 0)
            {
                break;
            }

            var entrySize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(found + 8, 4));
            if (entrySize < 10 || entrySize > 1_048_576 || found + 12L + entrySize > data.Length)
            {
                offset = found + 4;
                continue;
            }
            var payload = data.AsSpan(found + 12, (int)entrySize);
            var pathLength = BinaryPrimitives.ReadUInt16LittleEndian(payload);
            if (pathLength > 0 && pathLength <= payload.Length - 2 && pathLength % 2 == 0)
            {
                var path = Encoding.Unicode.GetString(payload.Slice(2, pathLength)).TrimEnd('\0');
                if (LooksLikeWindowsPath(path))
                {
                    entries.Add(new ShimcacheEntry(path, FindPlausibleFileTime(payload[(2 + pathLength)..]), false));
                }
            }
            offset = found + 12 + (int)entrySize;
        }

        return entries.Count > 0
            ? new ShimcacheParseResult(true, "Windows10/11-10ts", entries, "")
            : new ShimcacheParseResult(false, "Unknown", [],
                $"Unsupported AppCompatCache layout (header={Convert.ToHexString(data.AsSpan(0, Math.Min(16, data.Length)))}).");
    }

    private static Dictionary<string, DateTimeOffset?> ParseDestListTimestamps(byte[] data)
    {
        var result = new Dictionary<string, DateTimeOffset?>(StringComparer.OrdinalIgnoreCase);
        if (data.Length < 32)
        {
            return result;
        }
        var version = BinaryPrimitives.ReadUInt32LittleEndian(data);
        var fixedSize = version == 1 ? 114 : version is 3 or 4 ? 130 : 0;
        if (fixedSize == 0)
        {
            return result;
        }

        for (var offset = 32; offset + fixedSize <= data.Length;)
        {
            var pathChars = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + fixedSize - 2, 2));
            var total = fixedSize + pathChars * 2;
            if (pathChars > 32_767 || offset + total > data.Length)
            {
                break;
            }
            var streamNumber = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 88, 4));
            result[streamNumber.ToString("X")] = ReadFileTime(data, offset + 100);
            offset += total;
        }
        return result;
    }

    private static int FindLinkHeader(byte[] data, int start)
    {
        for (var i = start; i + 20 <= data.Length; i++)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(i, 4)) == 0x4C
                && data.AsSpan(i + 4, 16).SequenceEqual(LinkClsid))
            {
                return i;
            }
        }
        return -1;
    }

    private static void ExtractReadableStrings(ReadOnlySpan<byte> data, List<string> output)
    {
        ExtractUtf16Strings(data, minimumChars: 3, output);

        for (var i = 0; i < data.Length;)
        {
            if (!IsPrintable(data[i]))
            {
                i++;
                continue;
            }
            var start = i;
            while (i < data.Length && IsPrintable(data[i]))
            {
                i++;
            }
            if (i - start >= 4)
            {
                output.Add(Encoding.Latin1.GetString(data[start..i]));
            }
        }
    }

    /// <summary>
    /// Ищет строки UTF-16 с шагом в символ, а не в байт.
    ///
    /// Прежний поиск при неудаче сдвигался на один байт и потому мог начать
    /// чтение с середины пары. Байты имени «POCO X3 NFC» при таком сдвиге
    /// складываются в иероглифы «倀伀䌀伀» — а это буквы, так что чтение
    /// продолжалось и съедало начало имени. Дальше поиск подхватывал остаток
    /// « X3 NFC», и в отчёт попадал обрубок, выглядевший как имя папки.
    ///
    /// Строки в элементах оболочки лежат на границе символа, поэтому сдвиг на
    /// байт не находит ничего нового — он только портит настоящие имена.
    /// </summary>
    private static void ExtractUtf16Strings(ReadOnlySpan<byte> data, int minimumChars, List<string> output)
    {
        var index = 0;
        while (index + 1 < data.Length)
        {
            if (!IsReadableUtf16Char(data, index))
            {
                index += 2;
                continue;
            }

            var start = index;
            while (index + 1 < data.Length && IsReadableUtf16Char(data, index))
            {
                index += 2;
            }

            var charCount = (index - start) / 2;
            if (charCount >= minimumChars)
            {
                output.Add(Encoding.Unicode.GetString(data[start..index]));
            }
        }
    }

    private static bool IsReadableUtf16Char(ReadOnlySpan<byte> data, int index)
    {
        if (index + 1 >= data.Length)
        {
            return false;
        }

        var value = (char)(data[index] | (data[index + 1] << 8));
        if (char.IsControl(value) || char.IsSurrogate(value) || value == '\uFFFD')
        {
            return false;
        }

        return char.IsLetterOrDigit(value)
               || char.IsPunctuation(value)
               || char.IsSymbol(value)
               || value == ' ';
    }

    /// <summary>
    /// Подписи блоков, в которых оболочка хранит настоящее имя элемента:
    /// расширение с длинным именем файла и блоки устройств MTP.
    /// </summary>
    private static readonly uint[] NameBearingSignatures =
    [
        0xBEEF0004, // расширение с длинным именем файла или папки
        0xBEEF0026, // расширение с метками времени
        0x07192006, // папка устройства MTP
        0x10312005  // том устройства MTP
    ];

    /// <summary>
    /// Имена из элемента оболочки. Раньше бралась любая печатная строка, поэтому
    /// у телефона, подключённого по MTP, терялись имена папок: они лежат внутри
    /// блоков с подписью, а не в теле элемента.
    /// </summary>
    private static bool ExtractShellItemNames(ReadOnlySpan<byte> body, List<string> output)
    {
        var portableDevice = false;
        if (body.Length == 0)
        {
            return false;
        }

        // Элемент тома: буква диска записана однобайтовой строкой сразу за типом.
        if (body[0] == 0x2F && body.Length >= 4)
        {
            AddAsciiName(body, 1, output);
        }

        // Элемент сетевого расположения: сразу за признаками лежит сам адрес вида
        // «\\20.20.20.76\r0», а за ним — название сети. Без разбора по структуре
        // выбиралось название сети, и из отчёта пропадало, с какого сервера
        // открывали папку.
        if (body[0] == 0xC3 || (body[0] >= 0x41 && body[0] <= 0x4F))
        {
            AddAsciiName(body, 3, output);
        }

        // Сначала точное имя по структуре блока, и только потом — поиск строк.
        // Порядок важен: имя элемента выбирается как первое подходящее.
        foreach (var found in Occurrences(body, 0xBEEF0004))
        {
            var name = ReadLongName(body, found);
            if (name.Length > 0)
            {
                output.Add(name);
            }
        }

        foreach (var signature in NameBearingSignatures)
        {
            foreach (var found in Occurrences(body, signature))
            {
                ExtractUtf16Strings(body[(found + 4)..], minimumChars: 1, output);
                portableDevice |= signature is 0x07192006 or 0x10312005;
            }
        }

        return portableDevice;
    }

    private static void AddAsciiName(ReadOnlySpan<byte> body, int offset, List<string> output)
    {
        if (offset >= body.Length)
        {
            return;
        }

        var rest = body[offset..];
        var end = rest.IndexOf((byte)0);
        var name = Encoding.Latin1.GetString(end < 0 ? rest : rest[..end]).Trim();
        if (name.Length > 0)
        {
            output.Add(name);
        }
    }

    private static IEnumerable<int> Occurrences(ReadOnlySpan<byte> body, uint signature)
    {
        var found = new List<int>();
        var position = 0;
        while (position + 4 <= body.Length)
        {
            var next = IndexOfUInt32(body, signature, position);
            if (next < 0)
            {
                break;
            }

            found.Add(next);
            position = next + 4;
        }

        return found;
    }

    /// <summary>
    /// Длинное имя из расширения 0xBEEF0004 — ровно то имя, которое показывает
    /// проводник. Лежит оно по определённому структурой смещению, и брать его
    /// надо оттуда, а не искать в теле элемента любую печатную строку.
    ///
    /// Перед именем стоят двоичные поля, и последние два байта одного из них
    /// нередко складываются в печатный знак. Поиск строк подхватывал его вместе
    /// с именем: «Windows 10 by Eagle123» доходило до отчёта как
    /// «謕JWindows 10 by Eagle123», а «архиваторы» — как «¼архиваторы».
    /// </summary>
    private static string ReadLongName(ReadOnlySpan<byte> body, int signaturePosition)
    {
        var start = signaturePosition - 4;
        if (start < 0 || start + 4 > body.Length)
        {
            return "";
        }

        var size = BinaryPrimitives.ReadUInt16LittleEndian(body.Slice(start, 2));
        var version = BinaryPrimitives.ReadUInt16LittleEndian(body.Slice(start + 2, 2));
        if (version < 3 || start + size > body.Length)
        {
            return "";
        }

        var offset = 18; // подпись, две метки времени DOS и признак версии
        if (version >= 7)
        {
            offset += 18; // выравнивание и ссылка на запись файла NTFS
        }

        offset += 2; // размер длинной строки
        if (version >= 9)
        {
            offset += 4;
        }

        if (version >= 8)
        {
            offset += 4;
        }

        return offset + 2 <= size
            ? ReadTerminatedUtf16(body[(start + offset)..(start + size)])
            : "";
    }

    private static string ReadTerminatedUtf16(ReadOnlySpan<byte> data)
    {
        for (var index = 0; index + 1 < data.Length; index += 2)
        {
            if (data[index] == 0 && data[index + 1] == 0)
            {
                return Encoding.Unicode.GetString(data[..index]);
            }
        }

        return Encoding.Unicode.GetString(data[..(data.Length - data.Length % 2)]);
    }

    private static int IndexOfUInt32(ReadOnlySpan<byte> data, uint value, int start)
    {
        for (var i = Math.Max(0, start); i + 4 <= data.Length; i++)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(i, 4)) == value)
            {
                return i;
            }
        }

        return -1;
    }

    private static string CleanFragment(string value) =>
        value.Replace('\0', ' ').Trim(' ', '\t', '\r', '\n', '\u0001');

    private static bool IsUsefulFragment(string value) =>
        value.Length is >= 2 and <= 2048
        && value.Any(char.IsLetterOrDigit)
        && LooksLikeReadableName(value);

    /// <summary>
    /// Поиск строк идёт по двоичному телу элемента оболочки побайтно, поэтому
    /// начало строки иногда угадывается со сдвигом в один байт, и то же имя
    /// читается как набор иероглифов: "UsbForensicAudit" превращается в
    /// "唀猀戀䘀漀爀攀渀猀椀挀䄀甀搀椀琀". Двоичные GUID тем же способом дают "PàOÐ ê:i".
    /// В отчёте такой мусор выглядел как настоящий путь, куда заходил
    /// пользователь, поэтому фрагмент принимается, только если почти целиком
    /// состоит из знаков, которыми записываются имена файлов и папок.
    /// </summary>
    private static bool LooksLikeReadableName(string value)
    {
        var readable = value.Count(IsNameCharacter);
        return readable >= value.Length * 0.8;
    }

    private static bool IsNameCharacter(char value) =>
        value is >= ' ' and <= '~'
        || value is >= '\u0400' and <= '\u04FF'
        || value == '\u00A0'
        || value == '\u2014'
        || value == '\u2013'
        || value == '\u00AB'
        || value == '\u00BB'
        || value == '\u2026'
        || value == '\u2116';

    private static string ExtractVolumeGuid(string value)
    {
        var match = VolumeGuidRegex().Match(value);
        return match.Success ? match.Value : "";
    }

    private static bool IsPrintable(byte value) => value is >= 0x20 and <= 0x7E || value >= 0xA0;
    private static bool LooksLikeWindowsPath(string value) =>
        DrivePathRegex().IsMatch(value) || value.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)
        || value.StartsWith(@"\\", StringComparison.Ordinal);

    private static int IndexOfUInt32(byte[] data, uint value, int start)
    {
        for (var i = Math.Max(0, start); i + 4 <= data.Length; i++)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(i, 4)) == value)
            {
                return i;
            }
        }
        return -1;
    }

    private static DateTimeOffset? FindPlausibleFileTime(ReadOnlySpan<byte> data)
    {
        for (var offset = 0; offset + 8 <= data.Length; offset++)
        {
            var timestamp = ReadFileTime(data, offset);
            if (timestamp is not null)
            {
                return timestamp;
            }
        }
        return null;
    }

    private static DateTimeOffset? ReadFileTime(ReadOnlySpan<byte> data, int offset)
    {
        if (offset < 0 || offset + 8 > data.Length)
        {
            return null;
        }
        var value = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(offset, 8));
        try
        {
            var result = DateTimeOffset.FromFileTime(value).ToUniversalTime();
            return result.Year is >= 1995 and <= 2100 ? result : null;
        }
        catch
        {
            return null;
        }
    }

    [GeneratedRegex(@"(?i)(?:\\\\\?\\)?Volume\{[0-9a-f-]{36}\}")]
    private static partial Regex VolumeGuidRegex();
    [GeneratedRegex(@"(?i)(?:\\\\\?\\)?Volume\{[0-9a-f-]{36}\}")]
    private static partial Regex VolumePathRegex();
    [GeneratedRegex(@"(?i)\b[A-Z]:\\")]
    private static partial Regex DrivePathRegex();
    [GeneratedRegex(@"^\{[0-9a-f-]{36}\}$", RegexOptions.IgnoreCase)]
    private static partial Regex GuidOnlyRegex();
    [GeneratedRegex(@"^(?<drive>[A-Z]):[\\/]", RegexOptions.IgnoreCase)]
    private static partial Regex DriveLetterPrefixRegex();

    private static class CompoundFile
    {
        private const uint Free = 0xFFFFFFFF;
        private const uint End = 0xFFFFFFFE;

        internal static bool TryReadStreams(byte[] data, out Dictionary<string, byte[]> streams)
        {
            streams = new(StringComparer.OrdinalIgnoreCase);
            if (data.Length < 512 || !data.AsSpan(0, 8).SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }))
            {
                return false;
            }
            try
            {
                var sectorSize = 1 << BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(0x1E, 2));
                var miniSectorSize = 1 << BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(0x20, 2));
                var fatSectors = ReadDifat(data);
                var fat = fatSectors.SelectMany(s => ReadUInt32Sector(data, s, sectorSize)).ToArray();
                var directoryBytes = ReadChain(data, BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x30, 4)), fat, sectorSize, int.MaxValue);
                var directory = ReadDirectory(directoryBytes);
                var root = directory.FirstOrDefault(x => x.Type == 5);
                var miniStream = root is null ? [] : ReadChain(data, root.Start, fat, sectorSize, checked((int)Math.Min(root.Size, int.MaxValue)));
                var miniFat = ReadChain(data, BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x3C, 4)), fat, sectorSize, int.MaxValue);
                var miniFatEntries = ToUInt32Array(miniFat);
                var cutoff = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x38, 4));

                foreach (var entry in directory.Where(x => x.Type == 2 && x.Size <= 64 * 1024 * 1024))
                {
                    streams[entry.Name] = entry.Size < cutoff
                        ? ReadMiniChain(miniStream, entry.Start, miniFatEntries, miniSectorSize, (int)entry.Size)
                        : ReadChain(data, entry.Start, fat, sectorSize, (int)entry.Size);
                }
                return true;
            }
            catch
            {
                streams.Clear();
                return false;
            }
        }

        private static List<uint> ReadDifat(byte[] data)
        {
            var result = new List<uint>();
            for (var i = 0; i < 109; i++)
            {
                var value = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x4C + i * 4, 4));
                if (value != Free && value < 0xFFFFFFFA)
                {
                    result.Add(value);
                }
            }
            return result;
        }

        private static IEnumerable<uint> ReadUInt32Sector(byte[] data, uint sector, int sectorSize) =>
            ToUInt32Array(ReadSector(data, sector, sectorSize));

        private static byte[] ReadChain(byte[] data, uint start, uint[] fat, int sectorSize, int maxBytes)
        {
            using var output = new MemoryStream();
            var seen = new HashSet<uint>();
            for (var sector = start; sector != End && sector != Free && sector < fat.Length && seen.Add(sector) && output.Length < maxBytes; sector = fat[sector])
            {
                var bytes = ReadSector(data, sector, sectorSize);
                output.Write(bytes, 0, Math.Min(bytes.Length, maxBytes - (int)Math.Min(output.Length, int.MaxValue)));
            }
            var result = output.ToArray();
            return result.Length <= maxBytes ? result : result[..maxBytes];
        }

        private static byte[] ReadMiniChain(byte[] miniStream, uint start, uint[] miniFat, int size, int maxBytes)
        {
            using var output = new MemoryStream();
            var seen = new HashSet<uint>();
            for (var sector = start; sector != End && sector != Free && sector < miniFat.Length && seen.Add(sector) && output.Length < maxBytes; sector = miniFat[sector])
            {
                var offset = checked((int)sector * size);
                if (offset + size > miniStream.Length) break;
                output.Write(miniStream, offset, Math.Min(size, maxBytes - (int)output.Length));
            }
            return output.ToArray();
        }

        private static byte[] ReadSector(byte[] data, uint sector, int size)
        {
            var offset = checked(512 + (int)sector * size);
            if (offset < 0 || offset + size > data.Length) throw new InvalidDataException();
            return data.AsSpan(offset, size).ToArray();
        }

        private static uint[] ToUInt32Array(byte[] data)
        {
            var result = new uint[data.Length / 4];
            for (var i = 0; i < result.Length; i++)
            {
                result[i] = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(i * 4, 4));
            }
            return result;
        }

        private static List<DirectoryEntry> ReadDirectory(byte[] data)
        {
            var result = new List<DirectoryEntry>();
            for (var offset = 0; offset + 128 <= data.Length; offset += 128)
            {
                var nameBytes = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + 0x40, 2));
                var type = data[offset + 0x42];
                if (nameBytes < 2 || nameBytes > 64 || type is not (2 or 5)) continue;
                var name = Encoding.Unicode.GetString(data, offset, nameBytes - 2);
                var start = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 0x74, 4));
                var size = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset + 0x78, 8));
                result.Add(new DirectoryEntry(name, type, start, size));
            }
            return result;
        }

        private sealed record DirectoryEntry(string Name, byte Type, uint Start, ulong Size);
    }
}
