using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class BluetoothTests
{
    /// <summary>
    /// Класс 0x5A020C взят с живой машины: это телефон Galaxy, сопряжённый с
    /// рабочим компьютером. Число в отчёте бесполезно, а «телефон, смартфон»
    /// отвечает на вопрос, что подключали.
    /// </summary>
    [Fact]
    public void Device_class_of_the_paired_phone_is_named_in_words()
    {
        var text = BluetoothServiceCatalog.DescribeDeviceClass(0x5A020C);

        Assert.Equal("телефон, смартфон", text);
    }

    [Theory]
    [InlineData(0x000110, "компьютер, карманный компьютер")]
    [InlineData(0x24010C, "компьютер, ноутбук")]
    [InlineData(0x240410, "звуковое устройство, микрофон")]
    [InlineData(0x000540, "клавиатура, мышь или игровой пульт, клавиатура")]
    public void Known_classes_are_named(int classOfDevice, string expected) =>
        Assert.Equal(expected, BluetoothServiceCatalog.DescribeDeviceClass(classOfDevice));

    [Fact]
    public void Missing_class_gives_nothing_instead_of_a_made_up_kind()
    {
        Assert.Equal("", BluetoothServiceCatalog.DescribeDeviceClass(null));
        Assert.Equal("", BluetoothServiceCatalog.DescribeDeviceClass(0));
    }

    /// <summary>
    /// Возможности телефона с живой машины: раздача сети, съёмка, передача
    /// файлов, телефония. Передача файлов здесь важнее всего — это канал, по
    /// которому данные уходят без флешки.
    /// </summary>
    [Fact]
    public void Declared_abilities_include_file_transfer_and_network()
    {
        var abilities = BluetoothServiceCatalog.DescribeServiceClasses(0x5A020C);

        Assert.Contains("передача файлов", abilities);
        Assert.Contains("выход в сеть", abilities);
        Assert.Contains("телефония", abilities);
        Assert.DoesNotContain("определение местоположения", abilities);
    }

    [Theory]
    [InlineData("{00001105-0000-1000-8000-00805f9b34fb}", true)]
    [InlineData("{00001116-0000-1000-8000-00805f9b34fb}", true)]
    [InlineData("{0000112f-0000-1000-8000-00805f9b34fb}", true)]
    [InlineData("{0000110b-0000-1000-8000-00805f9b34fb}", false)]
    public void Services_that_move_data_are_marked_apart_from_the_rest(string uuid, bool expected)
    {
        Assert.True(BluetoothServiceCatalog.TryDescribe(uuid, out var description, out var notable));
        Assert.NotEmpty(description);
        Assert.Equal(expected, notable);
    }

    [Fact]
    public void Service_of_a_vendor_is_not_given_a_made_up_purpose()
    {
        // Опознаватель телефона Samsung: стандартной услуге он не соответствует, и
        // назначение ему приписывать нельзя.
        Assert.False(BluetoothServiceCatalog.TryDescribe(
            "{a49eb41e-cb06-495c-9f4f-bb80a90cdf00}", out _, out _));
    }

    [Fact]
    public void Unknown_standard_service_keeps_its_number_instead_of_a_guess()
    {
        Assert.True(BluetoothServiceCatalog.TryDescribe(
            "{00001999-0000-1000-8000-00805f9b34fb}", out var description, out var notable));
        Assert.Contains("0x1999", description);
        Assert.False(notable);
    }

    /// <summary>
    /// NFC проверяется всегда, даже когда оборудования нет: молчание об NFC
    /// читается как «ничего не передавали», а это разные утверждения.
    /// </summary>
    [Fact]
    public void Absence_of_near_field_hardware_is_stated_and_not_left_silent()
    {
        var record = NearFieldPresence.Describe();

        Assert.Equal("NFC на этой машине", record.EvidenceCategory);
        Assert.NotEmpty(record.Summary);
        Assert.NotEmpty(record.UserExplanation);
        Assert.Contains("Services", record.Provenance);
        Assert.False(record.CanEstablishConnectionDate);
    }
}
