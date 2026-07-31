using System.IO;
using System.Reflection;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Цвет строки и подпись категории раньше жили в разметке окна отдельно от
/// кода, который эти категории назначает. Категорию добавляли — цвет забывали,
/// и часть строк оставалась неокрашенной. Тесты держат перечни согласованными.
/// </summary>
public class DeviceCategoryPaletteTests
{
    /// <summary>
    /// Категории, которые проставляют сборщики и аналитические шаги.
    /// </summary>
    private static readonly string[] CategoriesUsedByCollectors =
    [
        "RealUsb", "RelatedStorage", "UsbFlagsTrace", "SupportArtifact", "HistoricalResidual"
    ];

    [Fact]
    public void Every_category_a_collector_can_assign_has_its_own_colour()
    {
        foreach (var category in CategoriesUsedByCollectors)
        {
            Assert.True(DeviceCategoryPalette.IsKnown(category), $"нет цвета для категории {category}");
        }
    }

    [Fact]
    public void Default_category_of_a_new_record_is_covered_too()
    {
        Assert.True(DeviceCategoryPalette.IsKnown(new UsbDeviceRecord().VisualCategory));
    }

    [Fact]
    public void Colours_are_distinct_so_categories_stay_distinguishable()
    {
        var backgrounds = DeviceCategoryPalette.KnownCategories
            .Select(x => DeviceCategoryPalette.For(x).Background)
            .ToArray();

        Assert.Equal(backgrounds.Length, backgrounds.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Unknown_category_is_painted_as_unparsed_not_as_a_service_record()
    {
        var unknown = DeviceCategoryPalette.For("СовершенноНоваяКатегория");

        Assert.Equal(DeviceCategoryPalette.For(DeviceCategoryPalette.Unclassified), unknown);
        Assert.NotEqual(DeviceCategoryPalette.For("SupportArtifact"), unknown);
    }

    [Fact]
    public void Empty_category_does_not_crash_the_grid()
    {
        Assert.NotNull(DeviceCategoryPalette.For(null).Background);
        Assert.NotNull(DeviceCategoryPalette.For("").Background);
    }

    [Theory]
    [InlineData("RealUsb")]
    [InlineData("RelatedStorage")]
    [InlineData("UsbFlagsTrace")]
    [InlineData("SupportArtifact")]
    [InlineData("HistoricalResidual")]
    public void Every_coloured_category_also_has_a_plain_russian_name(string category)
    {
        Assert.NotEqual("Не определено", UserDisplayText.Category(category));
    }

    [Fact]
    public void Colours_are_valid_hex_values()
    {
        foreach (var category in DeviceCategoryPalette.KnownCategories)
        {
            var colors = DeviceCategoryPalette.For(category);
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

        Assert.Contains("DeviceCategoryBrushConverter", rowStyle, StringComparison.Ordinal);
        Assert.DoesNotContain("VisualCategory}\" Value=", rowStyle, StringComparison.Ordinal);
    }

    private static string FindRepositoryFile(string fileName)
    {
        DirectoryInfo? directory = new(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Не найден файл {fileName} выше по дереву каталогов.");
    }
}
