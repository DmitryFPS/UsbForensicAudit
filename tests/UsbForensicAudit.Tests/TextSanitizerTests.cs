using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class TextSanitizerTests
{
    [Fact]
    public void Clean_collapses_whitespace_and_trims()
    {
        var result = TextSanitizer.Clean("  Kingston   DataTraveler  ");
        Assert.Equal("Kingston DataTraveler", result);
    }

    [Fact]
    public void RedactRestrictedTerms_replaces_secret_net()
    {
        var result = TextSanitizer.RedactRestrictedTerms("Secret Net Studio blocked USB");
        Assert.Contains("корпоративная защита USB", result, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Secret Net", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Clean_removes_control_characters()
    {
        var text = TextSanitizer.Clean("Kingston\u0001Drive");
        Assert.Equal("KingstonDrive", text);
        Assert.DoesNotContain('\u0001', text);
    }

    [Fact]
    public void LooksLikeMojibake_detects_replacement_chars()
    {
        Assert.True(TextSanitizer.LooksLikeMojibake("????????????????????"));
    }

    [Fact]
    public void NormalizeDisplay_keeps_usb_paths()
    {
        var text = TextSanitizer.NormalizeDisplay(@"C:\Users\test\file.txt");
        Assert.Contains(@"C:\Users", text);
    }

    [Fact]
    public void NormalizeDisplay_keeps_russian_text_with_separate_technical_acronym()
    {
        Assert.Equal("Отключение USB", TextSanitizer.NormalizeDisplay("Отключение USB"));
    }

    [Fact]
    public void IsReadableForDisplay_rejects_mixed_scripts_inside_one_token()
    {
        Assert.False(TextSanitizer.IsReadableForDisplay("РayРal"));
    }

    [Theory]
    [InlineData(@"USB\VID_2717&PID_FF40\8dde262e")]
    [InlineData(@"USBSTOR\Disk&Ven_General&Prod_UDisk&Rev_5.00\2412242109410569603146&0")]
    [InlineData(@"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2412281911546114543745&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}")]
    [InlineData(@"HKLM\SYSTEM\ControlSet001\Control\usbflags\2717FF400414")]
    public void NormalizeDisplay_preserves_device_identifiers_byte_for_byte(string identifier)
    {
        Assert.Equal(identifier, TextSanitizer.NormalizeDisplay(identifier, 4000));
    }

    [Fact]
    public void NormalizeDisplay_keeps_ampersand_in_plain_text()
    {
        Assert.Equal("General & UDisk", TextSanitizer.NormalizeDisplay("General & UDisk"));
    }

    [Fact]
    public void CleanIdentifier_strips_only_control_characters()
    {
        var result = TextSanitizer.CleanIdentifier("USB\\VID_2717&PID_FF40\u0001\\8dde262e");
        Assert.Equal(@"USB\VID_2717&PID_FF40\8dde262e", result);
    }

    [Fact]
    public void LooksLikeDeviceIdentifier_ignores_ordinary_prose()
    {
        Assert.False(TextSanitizer.LooksLikeDeviceIdentifier("Подключение внешнего накопителя"));
        Assert.True(TextSanitizer.LooksLikeDeviceIdentifier(@"Событие 1006: USB\VID_ABCD&PID_1234\2412"));
    }

    [Fact]
    public void NormalizeConsoleOutput_decodes_cp866_bytes()
    {
        Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
        var bytes = Encoding.GetEncoding(866).GetBytes("Тест USB");
        var text = TextSanitizer.NormalizeConsoleOutput(bytes);
        Assert.False(string.IsNullOrWhiteSpace(text));
    }
}
