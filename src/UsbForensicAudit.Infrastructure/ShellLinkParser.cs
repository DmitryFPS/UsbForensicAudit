using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace UsbForensicAudit;

public sealed class ShellLinkInfo
{
    public string LinkPath { get; init; } = "";
    public string LocalBasePath { get; init; } = "";
    public string CommonPathSuffix { get; init; } = "";

    /// <summary>
    /// Путь к сетевой папке, если файл открывали не с диска этой машины:
    /// «\\20.23.5.4\ModulsFiles». Ярлык хранит его отдельной структурой, и без
    /// неё у сетевого файла оставалось только его имя без всякого пути.
    /// </summary>
    public string NetworkPath { get; init; } = "";

    /// <summary>Буква диска, которой была подключена сетевая папка, если была.</summary>
    public string NetworkDeviceName { get; init; } = "";

    public string VolumeLabel { get; init; } = "";
    public string VolumeSerialNumber { get; init; } = "";
    public DateTimeOffset? CreationTimeUtc { get; init; }
    public DateTimeOffset? AccessTimeUtc { get; init; }
    public DateTimeOffset? WriteTimeUtc { get; init; }
    public IReadOnlyList<string> StringHints { get; init; } = [];

    /// <summary>
    /// Путь к тому, на что указывает ярлык. Для файла на диске это база плюс
    /// остаток пути, для файла на сервере — сетевая папка плюс тот же остаток.
    /// </summary>
    public string BestTarget => string.IsNullOrWhiteSpace(LocalBasePath) && NetworkPath.Length > 0
        ? CombinePath(NetworkPath, CommonPathSuffix)
        : CombinePath(LocalBasePath, CommonPathSuffix);

    private static string CombinePath(string left, string right)
    {
        if (string.IsNullOrWhiteSpace(left))
        {
            return right;
        }

        if (string.IsNullOrWhiteSpace(right))
        {
            return left;
        }

        var normalizedLeft = left.Replace('/', '\\').TrimEnd('\\');
        var normalizedRight = right.Replace('/', '\\').TrimStart('\\');
        // Ярлык описывает путь Windows, поэтому разделитель всегда «\».
        // Path.Join подставлял разделитель текущей ОС: при анализе артефактов
        // не на Windows цель ярлыка получала «/» в середине пути.
        return normalizedLeft + "\\" + normalizedRight;
    }
}

public static class ShellLinkParser
{
    private const uint LinkInfoFlagVolumeIdAndLocalBasePath = 0x1;
    private const uint LinkInfoFlagCommonNetworkRelativeLink = 0x2;
    private static readonly Encoding SystemAnsiEncoding = GetSystemAnsiEncoding();

    public static ShellLinkInfo? TryParse(string path)
    {
        try
        {
            return TryParse(File.ReadAllBytes(path), path);
        }
        catch
        {
            return null;
        }
    }

    internal static ShellLinkInfo? TryParse(byte[] data, string sourceName)
    {
        try
        {
            if (data.Length < 0x4C || ReadUInt32(data, 0) != 0x4C
                || !data.AsSpan(4, 16).SequenceEqual(new byte[]
                {
                    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
                }))
            {
                return null;
            }

            var linkFlags = ReadUInt32(data, 0x14);
            var hasLinkTargetIdList = (linkFlags & 0x1) != 0;
            var hasLinkInfo = (linkFlags & 0x2) != 0;
            var offset = 0x4C;

            if (hasLinkTargetIdList && data.Length >= offset + 2)
            {
                var idListSize = ReadUInt16(data, offset);
                offset += 2 + idListSize;
            }

            string localBasePath = "";
            string commonPathSuffix = "";
            string volumeLabel = "";
            string volumeSerial = "";
            string networkPath = "";
            string networkDeviceName = "";

            if (hasLinkInfo && data.Length >= offset + 0x1C)
            {
                ParseLinkInfo(data, offset, out localBasePath, out commonPathSuffix, out volumeLabel,
                    out volumeSerial, out networkPath, out networkDeviceName);
            }

            var hints = ExtractInterestingStrings(data, 20);

            return new ShellLinkInfo
            {
                LinkPath = sourceName,
                LocalBasePath = localBasePath,
                CommonPathSuffix = commonPathSuffix,
                NetworkPath = networkPath,
                NetworkDeviceName = networkDeviceName,
                VolumeLabel = volumeLabel,
                VolumeSerialNumber = volumeSerial,
                CreationTimeUtc = ReadFileTime(data, 0x1C),
                AccessTimeUtc = ReadFileTime(data, 0x24),
                WriteTimeUtc = ReadFileTime(data, 0x2C),
                StringHints = hints
            };
        }
        catch
        {
            return null;
        }
    }

    private static IReadOnlyList<string> ExtractInterestingStrings(byte[] data, int maxResults)
    {
        var results = new List<string>();
        foreach (var encoding in new[] { Encoding.Unicode, SystemAnsiEncoding })
        {
            var text = encoding.GetString(data, 0, Math.Min(data.Length, 512_000));
            foreach (var candidate in text.Split('\0', '\r', '\n')
                         .Select(x => x.Trim())
                         .Where(x => x.Length >= 3 && x.Length <= 2048 && ArtifactStringExtractor.LooksInteresting(x)))
            {
                if (!results.Contains(candidate, StringComparer.OrdinalIgnoreCase))
                {
                    results.Add(candidate);
                    if (results.Count >= maxResults)
                    {
                        return results;
                    }
                }
            }
        }
        return results;
    }

    private static void ParseLinkInfo(
        byte[] data,
        int offset,
        out string localBasePath,
        out string commonPathSuffix,
        out string volumeLabel,
        out string volumeSerial,
        out string networkPath,
        out string networkDeviceName)
    {
        localBasePath = "";
        commonPathSuffix = "";
        volumeLabel = "";
        volumeSerial = "";
        networkPath = "";
        networkDeviceName = "";

        var linkInfoSize = ReadUInt32(data, offset);
        if (linkInfoSize < 0x1C || offset + linkInfoSize > data.Length)
        {
            return;
        }

        var linkInfoHeaderSize = ReadUInt32(data, offset + 0x04);
        var linkInfoFlags = ReadUInt32(data, offset + 0x08);
        var volumeIdOffset = ReadUInt32(data, offset + 0x0C);
        var localBasePathOffset = ReadUInt32(data, offset + 0x10);
        var commonPathSuffixOffset = ReadUInt32(data, offset + 0x18);

        if ((linkInfoFlags & LinkInfoFlagVolumeIdAndLocalBasePath) != 0)
        {
            localBasePath = ReadNullTerminatedAnsi(data, offset + (int)localBasePathOffset, offset + (int)linkInfoSize);
            ParseVolumeId(data, offset + (int)volumeIdOffset, offset + (int)linkInfoSize, out volumeLabel, out volumeSerial);
        }

        // Остаток пути записан у ярлыка независимо от того, лежал файл на диске
        // или на сервере, а вот база пути в этих случаях лежит в разных местах.
        commonPathSuffix = ReadNullTerminatedAnsi(
            data, offset + (int)commonPathSuffixOffset, offset + (int)linkInfoSize);

        if ((linkInfoFlags & LinkInfoFlagCommonNetworkRelativeLink) != 0)
        {
            var networkOffset = ReadUInt32(data, offset + 0x14);
            ParseNetworkRelativeLink(
                data,
                offset + (int)networkOffset,
                offset + (int)linkInfoSize,
                out networkPath,
                out networkDeviceName);
        }

        if (linkInfoHeaderSize >= 0x24)
        {
            var localBasePathOffsetUnicode = ReadUInt32(data, offset + 0x1C);
            var commonPathSuffixOffsetUnicode = ReadUInt32(data, offset + 0x20);
            var unicodeLocal = ReadNullTerminatedUnicode(data, offset + (int)localBasePathOffsetUnicode, offset + (int)linkInfoSize);
            var unicodeSuffix = ReadNullTerminatedUnicode(data, offset + (int)commonPathSuffixOffsetUnicode, offset + (int)linkInfoSize);

            if (!string.IsNullOrWhiteSpace(unicodeLocal))
            {
                localBasePath = unicodeLocal;
            }

            if (!string.IsNullOrWhiteSpace(unicodeSuffix))
            {
                commonPathSuffix = unicodeSuffix;
            }
        }
    }

    /// <summary>
    /// Структура сетевой ссылки ярлыка: имя сетевой папки и буква диска, которой
    /// она была подключена. Имя лежит дважды — в однобайтовой кодировке и в
    /// двухбайтовой; вторая появляется только у ярлыков с именами вне латиницы,
    /// и предпочтение отдаётся ей.
    /// </summary>
    private static void ParseNetworkRelativeLink(
        byte[] data,
        int offset,
        int end,
        out string networkPath,
        out string deviceName)
    {
        networkPath = "";
        deviceName = "";

        if (offset <= 0 || offset + 0x14 > end || offset + 0x14 > data.Length)
        {
            return;
        }

        var size = ReadUInt32(data, offset);
        if (size < 0x14 || offset + size > end)
        {
            return;
        }

        var limit = offset + (int)size;
        var netNameOffset = ReadUInt32(data, offset + 0x08);
        var deviceNameOffset = ReadUInt32(data, offset + 0x0C);

        networkPath = ReadNullTerminatedAnsi(data, offset + (int)netNameOffset, limit);
        deviceName = ReadNullTerminatedAnsi(data, offset + (int)deviceNameOffset, limit);

        if (netNameOffset <= 0x14)
        {
            return;
        }

        var unicodeNetName = ReadNullTerminatedUnicode(data, offset + (int)ReadUInt32(data, offset + 0x14), limit);
        if (!string.IsNullOrWhiteSpace(unicodeNetName))
        {
            networkPath = unicodeNetName;
        }

        var unicodeDeviceName = ReadNullTerminatedUnicode(data, offset + (int)ReadUInt32(data, offset + 0x18), limit);
        if (!string.IsNullOrWhiteSpace(unicodeDeviceName))
        {
            deviceName = unicodeDeviceName;
        }
    }

    private static void ParseVolumeId(byte[] data, int offset, int end, out string volumeLabel, out string volumeSerial)
    {
        volumeLabel = "";
        volumeSerial = "";

        if (offset <= 0 || offset + 0x10 > end)
        {
            return;
        }

        var volumeIdSize = ReadUInt32(data, offset);
        if (volumeIdSize < 0x10 || offset + volumeIdSize > end)
        {
            return;
        }

        var serial = ReadUInt32(data, offset + 0x08);
        volumeSerial = serial == 0 ? "" : serial.ToString("X8");
        var labelOffset = ReadUInt32(data, offset + 0x0C);
        volumeLabel = ReadNullTerminatedAnsi(data, offset + (int)labelOffset, offset + (int)volumeIdSize);
    }

    private static DateTimeOffset? ReadFileTime(byte[] data, int offset)
    {
        if (offset + 8 > data.Length)
        {
            return null;
        }

        var value = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(offset, 8));
        if (value <= 0)
        {
            return null;
        }

        try
        {
            return DateTimeOffset.FromFileTime(value).ToUniversalTime();
        }
        catch
        {
            return null;
        }
    }

    private static ushort ReadUInt16(byte[] data, int offset)
    {
        return BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2));
    }

    private static uint ReadUInt32(byte[] data, int offset)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
    }

    private static string ReadNullTerminatedAnsi(byte[] data, int offset, int end)
    {
        if (offset <= 0 || offset >= data.Length || offset >= end)
        {
            return "";
        }

        var length = 0;
        while (offset + length < data.Length && offset + length < end && data[offset + length] != 0)
        {
            length++;
        }

        return length == 0 ? "" : SystemAnsiEncoding.GetString(data, offset, length).Trim();
    }

    private static string ReadNullTerminatedUnicode(byte[] data, int offset, int end)
    {
        if (offset <= 0 || offset + 1 >= data.Length || offset >= end)
        {
            return "";
        }

        var length = 0;
        while (offset + length + 1 < data.Length && offset + length + 1 < end)
        {
            if (data[offset + length] == 0 && data[offset + length + 1] == 0)
            {
                break;
            }

            length += 2;
        }

        return length == 0 ? "" : Encoding.Unicode.GetString(data, offset, length).Trim();
    }

    private static Encoding GetSystemAnsiEncoding()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        try
        {
            return Encoding.GetEncoding(1251);
        }
        catch
        {
            return Encoding.UTF8;
        }
    }
}
