using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

internal sealed record PidlArtifact(IReadOnlyList<string> PathFragments, string BestPath, string VolumeGuid);
internal sealed record ShellBagArtifact(string Path, int? Slot, bool IsUsbRelevant);
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

            ExtractReadableStrings(bytes.AsSpan(offset + 2, size - 2), fragments);
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
        var bestPath = unique
            .Where(x => DrivePathRegex().IsMatch(x) || VolumePathRegex().IsMatch(x) || x.Contains('\\'))
            .OrderByDescending(x => x.Length)
            .FirstOrDefault() ?? string.Join("\\", unique.Where(x => !GuidOnlyRegex().IsMatch(x)).Take(12));
        return new PidlArtifact(unique, bestPath, volume);
    }

    internal static ShellBagArtifact ParseShellBagNode(byte[]? value, string parentPath, int? slot)
    {
        var pidl = ParsePidl(value);
        var fragment = pidl.BestPath;
        var path = string.IsNullOrWhiteSpace(parentPath)
            ? fragment
            : string.IsNullOrWhiteSpace(fragment) ? parentPath : $"{parentPath.TrimEnd('\\')}\\{fragment.TrimStart('\\')}";
        return new ShellBagArtifact(path, slot, IsUsbOrVolumeMarker(path + " " + pidl.VolumeGuid));
    }

    internal static bool IsUsbOrVolumeMarker(string value) =>
        value.Contains("USB", StringComparison.OrdinalIgnoreCase)
        || value.Contains("WPDBUSENUM", StringComparison.OrdinalIgnoreCase)
        || value.Contains("WPD", StringComparison.OrdinalIgnoreCase)
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
        for (var i = 0; i + 5 < data.Length;)
        {
            if (data[i + 1] == 0 && IsPrintable(data[i]))
            {
                var start = i;
                while (i + 1 < data.Length && data[i + 1] == 0 && (IsPrintable(data[i]) || data[i] == 0))
                {
                    i += 2;
                }
                if (i - start >= 6)
                {
                    output.Add(Encoding.Unicode.GetString(data[start..i]));
                }
            }
            else
            {
                i++;
            }
        }

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

    private static string CleanFragment(string value) =>
        value.Replace('\0', ' ').Trim(' ', '\t', '\r', '\n', '\u0001');

    private static bool IsUsefulFragment(string value) =>
        value.Length is >= 2 and <= 2048 && value.Any(char.IsLetterOrDigit);

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
