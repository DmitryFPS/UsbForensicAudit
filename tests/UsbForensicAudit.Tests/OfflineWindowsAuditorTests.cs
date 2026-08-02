using System.IO;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Офлайн-аудит: определение каталога Windows по переданному корню и разбор
/// имён веток USBSTOR. Сами кусты реестра в тестах не монтируются — reg load
/// требует Windows и прав администратора, а разбор имён от них не зависит.
/// </summary>
public sealed class OfflineWindowsAuditorTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(), "ufa-offline-tests", Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, true);
            }
        }
        catch (IOException)
        {
            // Временную папку уберёт следующая чистка temp.
        }
    }

    private string CreateSystemHive(params string[] pathSegments)
    {
        var directory = Path.Combine([_root, .. pathSegments, "System32", "config"]);
        Directory.CreateDirectory(directory);
        var hive = Path.Combine(directory, "SYSTEM");
        File.WriteAllBytes(hive, [1, 2, 3]);
        return hive;
    }

    [Fact]
    public void FindWindowsDirectory_ПринимаетКореньДиска()
    {
        CreateSystemHive("Windows");

        var found = OfflineWindowsAuditor.FindWindowsDirectory(_root);

        Assert.NotNull(found);
        Assert.EndsWith("Windows", found);
    }

    [Fact]
    public void FindWindowsDirectory_ПринимаетСамКаталогWindows()
    {
        CreateSystemHive("Windows");

        var found = OfflineWindowsAuditor.FindWindowsDirectory(Path.Combine(_root, "Windows"));

        Assert.NotNull(found);
        Assert.EndsWith("Windows", found);
    }

    [Fact]
    public void FindWindowsDirectory_БезКустаSystem_ВозвращаетNull()
    {
        Directory.CreateDirectory(Path.Combine(_root, "Windows", "System32"));

        Assert.Null(OfflineWindowsAuditor.FindWindowsDirectory(_root));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void FindWindowsDirectory_ПустойПуть_ВозвращаетNull(string? root)
    {
        Assert.Null(OfflineWindowsAuditor.FindWindowsDirectory(root!));
    }

    [Fact]
    public void Audit_БезКаталогаWindows_БросаетПонятнуюОшибку()
    {
        Directory.CreateDirectory(_root);
        var auditor = new OfflineWindowsAuditor();

        var exception = Assert.Throws<DirectoryNotFoundException>(() => auditor.Audit(_root));

        Assert.Contains("Windows", exception.Message);
        Assert.Contains(_root, exception.Message);
    }

    [Fact]
    public void ParseUsbStorModel_РазбираетСтандартноеИмя()
    {
        var (vendor, product, revision) = OfflineWindowsAuditor.ParseUsbStorModel(
            "Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP");

        Assert.Equal("Kingston", vendor);
        Assert.Equal("DataTraveler 3.0", product);
        Assert.Equal("PMAP", revision);
    }

    [Fact]
    public void ParseUsbStorModel_БезИзвестныхЧастей_ВозвращаетПустое()
    {
        var (vendor, product, revision) = OfflineWindowsAuditor.ParseUsbStorModel("CdRom");

        Assert.Equal("", vendor);
        Assert.Equal("", product);
        Assert.Equal("", revision);
    }

    [Theory]
    [InlineData("0019E06B9C85F961A72300A5&0", "0019E06B9C85F961A72300A5")]
    [InlineData("SERIAL&1", "SERIAL")]
    [InlineData("SERIAL", "SERIAL")]
    [InlineData("&0", "&0")]
    public void TrimSerialSuffix_УбираетТолькоСчётчикЭкземпляра(string raw, string expected)
    {
        Assert.Equal(expected, OfflineWindowsAuditor.TrimSerialSuffix(raw));
    }
}
