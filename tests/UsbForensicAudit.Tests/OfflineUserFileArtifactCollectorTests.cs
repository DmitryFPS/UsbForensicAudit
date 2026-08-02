using System.Buffers.Binary;
using System.IO;
using System.Text;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Офлайн-сбор LNK и Jump Lists из профилей исследуемого образа: ярлык на файл
/// со съёмного носителя попадает в доказательства с именем пользователя, мусор
/// и посторонние цели отфильтровываются, отсутствие каталогов не считается ошибкой.
/// </summary>
public sealed class OfflineUserFileArtifactCollectorTests
{
    [Fact]
    public void Collect_UsbLinkInRecent_ProducesEvidenceWithUser()
    {
        var root = CreateImage();
        try
        {
            var recent = Path.Combine(
                root, "Users", "ivanov", "AppData", "Roaming", "Microsoft", "Windows", "Recent");
            Directory.CreateDirectory(recent);
            File.WriteAllBytes(
                Path.Combine(recent, "report.lnk"),
                BuildShellLink(@"E:\Секретно\отчёт.xlsx", volumeSerial: 0xAABBCCDD));

            var result = new AuditResult();
            var warnings = new List<string>();
            OfflineUserFileArtifactCollector.Collect(
                Path.Combine(root, "Users"), result, warnings, CancellationToken.None);

            var record = Assert.Single(result.Evidence);
            Assert.Equal("Offline User LNK", record.Source);
            Assert.Equal("ivanov", record.ResolvedUserName);
            Assert.Contains(@"E:\Секретно\отчёт.xlsx", record.Summary);
            Assert.Contains("AABBCCDD", record.RawText);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Collect_MissingProfileDirectories_NoEvidenceNoWarnings()
    {
        var root = CreateImage();
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "Users", "empty"));

            var result = new AuditResult();
            var warnings = new List<string>();
            OfflineUserFileArtifactCollector.Collect(
                Path.Combine(root, "Users"), result, warnings, CancellationToken.None);

            Assert.Empty(result.Evidence);
            Assert.Empty(warnings);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Collect_CorruptLnkFile_IsSkippedWithoutCrash()
    {
        var root = CreateImage();
        try
        {
            var desktop = Path.Combine(root, "Users", "petrov", "Desktop");
            Directory.CreateDirectory(desktop);
            File.WriteAllBytes(Path.Combine(desktop, "broken.lnk"), [0x01, 0x02, 0x03]);

            var result = new AuditResult();
            var warnings = new List<string>();
            OfflineUserFileArtifactCollector.Collect(
                Path.Combine(root, "Users"), result, warnings, CancellationToken.None);

            Assert.Empty(result.Evidence);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Collect_MissingUsersDirectory_ReturnsSilently()
    {
        var result = new AuditResult();
        var warnings = new List<string>();

        OfflineUserFileArtifactCollector.Collect(
            Path.Combine(Path.GetTempPath(), $"ufa-none-{Guid.NewGuid():N}"),
            result, warnings, CancellationToken.None);

        Assert.Empty(result.Evidence);
        Assert.Empty(warnings);
    }

    private static string CreateImage()
    {
        var root = Path.Combine(Path.GetTempPath(), $"ufa-offlnk-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        return root;
    }

    private static readonly byte[] LinkClsid =
    [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    ];

    /// <summary>
    /// Минимальный корректный Shell Link с LinkInfo и томом — тот же формат,
    /// что собирает BuildShellLink в MaturityCoverageParserTests.
    /// </summary>
    private static byte[] BuildShellLink(string localPath, uint volumeSerial)
    {
        const int linkInfoOffset = 0x4C;
        var data = new byte[1024];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 0x4C);
        LinkClsid.CopyTo(data, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x14, 4), 0x2u);

        const int headerSize = 0x24;
        const int volumeOffset = headerSize;
        const int volumeSize = 0x20;
        var cursor = volumeOffset + volumeSize;
        var ansiLocalOffset = cursor;
        cursor += WriteString(data, linkInfoOffset + cursor, localPath, Encoding.Latin1);
        var ansiSuffixOffset = cursor;
        cursor += WriteString(data, linkInfoOffset + cursor, "", Encoding.Latin1);
        var unicodeLocalOffset = cursor;
        cursor += WriteString(data, linkInfoOffset + cursor, localPath, Encoding.Unicode);
        var unicodeSuffixOffset = cursor;
        cursor += WriteString(data, linkInfoOffset + cursor, "", Encoding.Unicode);

        var info = data.AsSpan(linkInfoOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(info, checked((uint)cursor));
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(4, 4), headerSize);
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(8, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(12, 4), volumeOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(16, 4), checked((uint)ansiLocalOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(24, 4), checked((uint)ansiSuffixOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(28, 4), checked((uint)unicodeLocalOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(info.Slice(32, 4), checked((uint)unicodeSuffixOffset));

        var volume = info.Slice(volumeOffset, volumeSize);
        BinaryPrimitives.WriteUInt32LittleEndian(volume, volumeSize);
        BinaryPrimitives.WriteUInt32LittleEndian(volume.Slice(8, 4), volumeSerial);
        BinaryPrimitives.WriteUInt32LittleEndian(volume.Slice(12, 4), 0x10);
        WriteString(data, linkInfoOffset + volumeOffset + 0x10, "USB", Encoding.Latin1);

        Array.Resize(ref data, linkInfoOffset + cursor);
        return data;
    }

    private static int WriteString(byte[] data, int offset, string value, Encoding encoding)
    {
        var bytes = encoding.GetBytes(value + "\0");
        bytes.CopyTo(data, offset);
        return bytes.Length;
    }
}
