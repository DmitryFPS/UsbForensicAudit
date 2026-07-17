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

    [Fact]
    public void NormalizeConsoleOutput_decodes_cp866_bytes()
    {
        Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
        var bytes = Encoding.GetEncoding(866).GetBytes("Тест USB");
        var text = TextSanitizer.NormalizeConsoleOutput(bytes);
        Assert.False(string.IsNullOrWhiteSpace(text));
    }
}
