using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Имена в элементах оболочки ищутся в двоичном теле побайтно, поэтому начало
/// строки иногда угадывается со сдвигом: "UsbForensicAudit" читается как
/// "唀猀戀䘀漀爀攀渀猀椀挀䄀甀搀椀琀", а двоичный GUID — как "PàOÐ ê:i". Такой мусор
/// показывался пользователю как путь, куда он заходил на съёмном носителе.
/// </summary>
public class ShellBagReadabilityTests
{
    [Fact]
    public void Byte_shifted_utf16_garbage_does_not_become_a_path()
    {
        var pidl = ForensicArtifactParsers.ParsePidl(BuildPidl(
            Encoding.Unicode.GetBytes("唀猀戀䘀漀爀攀渀猀椀挀䄀甀搀椀琀")));

        Assert.DoesNotContain(pidl.PathFragments, x => x.Contains('唀'));
        Assert.Equal("", pidl.BestPath);
    }

    [Fact]
    public void Binary_guid_read_as_latin_text_does_not_become_a_path()
    {
        var pidl = ForensicArtifactParsers.ParsePidl(BuildPidl(
            [0x50, 0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0xA4, 0xE3, 0x36, 0x43, 0xA1, 0xF3]));

        Assert.DoesNotContain(pidl.PathFragments, x => x.Contains('Ð'));
    }

    [Fact]
    public void Cyrillic_folder_name_is_still_read()
    {
        var pidl = ForensicArtifactParsers.ParsePidl(BuildPidl(
            Encoding.Unicode.GetBytes("Фотографии с телефона")));

        Assert.Contains("Фотографии с телефона", pidl.PathFragments);
    }

    [Fact]
    public void Latin_folder_name_is_still_read()
    {
        var pidl = ForensicArtifactParsers.ParsePidl(BuildPidl(
            Encoding.Unicode.GetBytes(@"E:\Documents")));

        Assert.Equal(@"E:\Documents", pidl.BestPath);
    }

    private static byte[] BuildPidl(byte[] body)
    {
        var size = (ushort)(body.Length + 2);
        var result = new byte[size + 2];
        result[0] = (byte)(size & 0xFF);
        result[1] = (byte)(size >> 8);
        body.CopyTo(result, 2);
        return result;
    }
}
