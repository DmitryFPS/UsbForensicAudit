using System.IO;
using System.Reflection;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Цвет строки раньше жил в разметке окна отдельно от кода, который группы
/// назначает: группу добавляли — цвет забывали, и часть строк оставалась
/// неокрашенной. Тесты держат перечни согласованными.
/// </summary>
public class DeviceExternalityPaletteTests
{
    private static readonly string[] GroupsUsedByResolver =
    [
        DeviceExternality.ExternalMedia, DeviceExternality.ExternalPeripheral,
        DeviceExternality.PossiblyExternal, DeviceExternality.BuiltInDevice,
        DeviceExternality.BusInfrastructure, DeviceExternality.VirtualDevice,
        DeviceExternality.RegistryTrace, DeviceExternality.Undetermined
    ];

    [Fact]
    public void Every_group_the_resolver_can_assign_has_its_own_colour()
    {
        foreach (var group in GroupsUsedByResolver)
        {
            Assert.True(DeviceExternalityPalette.IsKnown(group), $"нет цвета для группы {group}");
        }
    }

    [Fact]
    public void Colours_are_distinct_so_groups_stay_distinguishable()
    {
        var backgrounds = DeviceExternalityPalette.KnownGroups
            .Select(x => DeviceExternalityPalette.For(x).Background)
            .ToArray();

        Assert.Equal(backgrounds.Length, backgrounds.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Unrecognised_group_is_painted_as_unparsed()
    {
        var unknown = DeviceExternalityPalette.For("СовершенноНоваяГруппа");

        Assert.Equal(DeviceExternalityPalette.For(DeviceExternality.Undetermined), unknown);
        Assert.NotEqual(DeviceExternalityPalette.For(DeviceExternality.ExternalMedia), unknown);
    }

    [Fact]
    public void Empty_group_does_not_crash_the_grid()
    {
        Assert.NotNull(DeviceExternalityPalette.For(null).Background);
        Assert.NotNull(DeviceExternalityPalette.For("").Background);
    }

    [Fact]
    public void Every_group_has_a_plain_russian_explanation()
    {
        foreach (var group in GroupsUsedByResolver)
        {
            Assert.False(string.IsNullOrWhiteSpace(DeviceExternality.Describe(group)));
        }
    }

    [Theory]
    [InlineData("RealUsb")]
    [InlineData("RelatedStorage")]
    [InlineData("UsbFlagsTrace")]
    [InlineData("SupportArtifact")]
    [InlineData("HistoricalResidual")]
    public void Every_record_category_still_has_a_plain_russian_name(string category)
    {
        Assert.NotEqual("Не определено", UserDisplayText.Category(category));
    }

    [Fact]
    public void Colours_are_valid_hex_values()
    {
        foreach (var group in DeviceExternalityPalette.KnownGroups)
        {
            var colors = DeviceExternalityPalette.For(group);
            Assert.Matches("^#[0-9A-Fa-f]{6}$", colors.Background);
            Assert.Matches("^#[0-9A-Fa-f]{6}$", colors.Foreground);
        }
    }

    /// <summary>
    /// Разметка окна не должна снова обзавестись собственным списком цветов:
    /// именно так и появилось расхождение.
    /// </summary>
    [Fact]
    public void Devices_grid_takes_its_colours_from_the_palette()
    {
        var markup = File.ReadAllText(FindRepositoryFile("MainWindow.xaml"));
        var devicesGrid = markup[markup.IndexOf("x:Name=\"DevicesGrid\"", StringComparison.Ordinal)..];
        var rowStyle = devicesGrid[..devicesGrid.IndexOf("</DataGrid.RowStyle>", StringComparison.Ordinal)];

        Assert.Contains("DeviceExternalityBrushConverter", rowStyle, StringComparison.Ordinal);
        Assert.DoesNotContain("VisualCategory", rowStyle, StringComparison.Ordinal);
    }

    private static string FindRepositoryFile(string fileName)
    {
        DirectoryInfo? directory = new(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "UsbForensicAudit.sln")))
            {
                var matches = Directory.GetFiles(directory.FullName, fileName, SearchOption.AllDirectories);
                if (matches.Length > 0)
                {
                    return matches[0];
                }

                break;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Не найден файл {fileName} в репозитории.");
    }
}
