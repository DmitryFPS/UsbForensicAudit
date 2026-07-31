using System;
using System.Collections.Generic;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Имя папки берётся из структуры элемента оболочки, а не поиском печатных строк
/// в его теле.
///
/// Поиск строк давал имена с прилипшим спереди знаком: перед именем в элементе
/// стоят двоичные поля, и последние их байты нередко складываются в печатный
/// символ. В отчёте это выглядело как «謕JWindows 10 by Eagle123» и
/// «¼архиваторы» — читателю оставалось догадываться, что за папку открывали.
/// </summary>
public class ShellItemNameTests
{
    [Theory]
    [InlineData("Windows 10 by Eagle123")]
    [InlineData("архиваторы")]
    [InlineData("Отчёты за 2026 год")]
    public void Long_name_is_read_without_the_binary_byte_in_front(string folder)
    {
        var artifact = ForensicArtifactParsers.ParseShellBagNode(
            BuildFolderItem(folder), parentPath: @"D:\Софт", slot: 1, systemDrive: "C:");

        Assert.Equal($@"D:\Софт\{folder}", artifact.Path);
    }

    /// <summary>
    /// Сетевое расположение: адрес сервера должен остаться в пути. Рядом с ним
    /// элемент хранит название сети, и раньше в путь попадало именно оно — из
    /// отчёта пропадало, с какого сервера открывали папку.
    /// </summary>
    [Fact]
    public void Network_item_keeps_the_server_address()
    {
        var artifact = ForensicArtifactParsers.ParseShellBagNode(
            BuildNetworkItem(@"\\20.20.20.76\r0", "Microsoft Network"), parentPath: "", slot: 1);

        Assert.Equal(@"\\20.20.20.76\r0", artifact.Path);
    }

    [Fact]
    public void Drive_item_starts_the_path_with_one_separator()
    {
        var artifact = ForensicArtifactParsers.ParseShellBagNode(
            BuildVolumeItem(@"E:\"), parentPath: "", slot: 1);
        var folder = ForensicArtifactParsers.ParseShellBagNode(
            BuildFolderItem("Фото"), parentPath: artifact.Path, slot: 2, systemDrive: "C:");

        Assert.Equal(@"E:\", artifact.Path);
        Assert.Equal(@"E:\Фото", folder.Path);
    }

    /// <summary>
    /// Часть элементов хранит имя однобайтовой строкой, и тот же однобайтовый
    /// проход читает как текст любые двоичные поля. Так в отчёт попадали
    /// «корневые папки» «1SPSsCå» и «Yr?§D».
    /// </summary>
    [Theory]
    [InlineData(new byte[] { 0x31, 0x53, 0x50, 0x53, 0x73, 0x43, 0xE5 })]
    [InlineData(new byte[] { 0x59, 0x72, 0x3F, 0xA7, 0x44 })]
    public void Binary_read_as_single_byte_text_is_not_a_folder_name(byte[] binary)
    {
        var pidl = ForensicArtifactParsers.ParsePidl(BuildItem(binary));

        Assert.Equal("", pidl.BestPath);
    }

    /// <summary>Элемент папки с расширением 0xBEEF0004 версии 9, как его пишет Windows 10.</summary>
    private static byte[] BuildFolderItem(string name)
    {
        var extension = new List<byte>();
        extension.AddRange([0, 0]);                    // размер блока, заполняется ниже
        extension.AddRange([9, 0]);                    // версия
        extension.AddRange([0x04, 0x00, 0xEF, 0xBE]);  // подпись
        extension.AddRange(new byte[8]);               // метки времени DOS
        extension.AddRange([0x2E, 0x00]);              // признак версии
        extension.AddRange(new byte[2]);               // выравнивание
        extension.AddRange(new byte[8]);               // ссылка на запись файла NTFS
        extension.AddRange(new byte[8]);               // не используется
        extension.AddRange(new byte[2]);               // размер длинной строки
        extension.AddRange(new byte[4]);               // поле версии 9
        // Двоичное поле, последние байты которого читаются как печатный знак:
        // именно он прилипал к имени спереди.
        extension.AddRange([0x6D, 0xF0, 0xBC, 0x00]);
        extension.AddRange(Encoding.Unicode.GetBytes(name));
        extension.AddRange([0, 0]);                    // конец строки
        extension.AddRange([0, 0]);                    // смещение первого расширения

        var size = (ushort)extension.Count;
        extension[0] = (byte)(size & 0xFF);
        extension[1] = (byte)(size >> 8);

        var body = new List<byte> { 0x31, 0x00 };
        body.AddRange(new byte[6]);                    // размер и метка времени
        body.AddRange(Encoding.Latin1.GetBytes("SHORT~1"));
        body.Add(0);
        body.AddRange(extension);
        return BuildItem(body.ToArray());
    }

    private static byte[] BuildVolumeItem(string drive)
    {
        var body = new List<byte> { 0x2F };
        body.AddRange(Encoding.Latin1.GetBytes(drive));
        body.AddRange(new byte[20]);
        return BuildItem(body.ToArray());
    }

    private static byte[] BuildNetworkItem(string location, string network)
    {
        var body = new List<byte> { 0xC3, 0x01, 0xD1 };
        body.AddRange(Encoding.Latin1.GetBytes(location));
        body.Add(0);
        body.AddRange(Encoding.Latin1.GetBytes(network));
        body.Add(0);
        return BuildItem(body.ToArray());
    }

    /// <summary>Оборачивает тело элемента в список PIDL: размер, тело, признак конца.</summary>
    private static byte[] BuildItem(byte[] body)
    {
        var size = (ushort)(body.Length + 2);
        var bytes = new List<byte> { (byte)(size & 0xFF), (byte)(size >> 8) };
        bytes.AddRange(body);
        bytes.AddRange([0, 0]);
        return bytes.ToArray();
    }
}
