using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace UsbForensicAudit;

public sealed class ShellLinkInfo
{
    public string LinkPath { get; init; } = "";
    public string LocalBasePath { get; init; } = "";
    public string CommonPathSuffix { get; init; } = "";
    public string VolumeLabel { get; init; } = "";
    public string VolumeSerialNumber { get; init; } = "";
    public DateTimeOffset? CreationTimeUtc { get; init; }
    public DateTimeOffset? AccessTimeUtc { get; init; }
    public DateTimeOffset? WriteTimeUtc { get; init; }
    public IReadOnlyList<string> StringHints { get; init; } = [];

    public string BestTarget => CombinePath(LocalBasePath, CommonPathSuffix);

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
        return Path.Join(normalizedLeft, normalizedRight);
    }
}

public static class ShellLinkParser
{
    private const uint LinkInfoFlagVolumeIdAndLocalBasePath = 0x1;
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

            if (hasLinkInfo && data.Length >= offset + 0x1C)
            {
                ParseLinkInfo(data, offset, out localBasePath, out commonPathSuffix, out volumeLabel, out volumeSerial);
            }

            var hints = ExtractInterestingStrings(data, 20);

            return new ShellLinkInfo
            {
                LinkPath = sourceName,
                LocalBasePath = localBasePath,
                CommonPathSuffix = commonPathSuffix,
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

    private static void ParseLinkInfo(byte[] data, int offset, out string localBasePath, out string commonPathSuffix, out string volumeLabel, out string volumeSerial)
    {
        localBasePath = "";
        commonPathSuffix = "";
        volumeLabel = "";
        volumeSerial = "";

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
            commonPathSuffix = ReadNullTerminatedAnsi(data, offset + (int)commonPathSuffixOffset, offset + (int)linkInfoSize);
            ParseVolumeId(data, offset + (int)volumeIdOffset, offset + (int)linkInfoSize, out volumeLabel, out volumeSerial);
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
