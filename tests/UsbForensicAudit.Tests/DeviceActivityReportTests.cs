using System;
using System.IO;
using System.Linq;
using ClosedXML.Excel;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// История работы на устройстве должна попадать во все отчёты, а не только в
/// окно программы: печатный отчёт читают те, у кого программы нет.
/// </summary>
public class DeviceActivityReportTests
{
    private static readonly DateTimeOffset Moment = new(2026, 3, 14, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Html_dossier_shows_what_was_done_on_the_device()
    {
        var html = ForensicReportBuilder.BuildHtml(ResultWithActivity());

        Assert.Contains("Что делали на устройстве", html);
        Assert.Contains("Открывали папку в проводнике", html);
        Assert.Contains(@"E:\Фото\Отпуск", html);
        Assert.Contains("Признаки копирования", html);
        Assert.Contains("Windows не ведёт журнал копирования", html);
    }

    [Fact]
    public void Html_summary_says_how_many_devices_have_a_file_history()
    {
        var html = ForensicReportBuilder.BuildHtml(ResultWithActivity());

        Assert.Contains("Восстановлена работа с файлами по 1 устройствам", html);
    }

    [Fact]
    public void Excel_report_has_a_sheet_with_device_activity()
    {
        var directory = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var path = new ReportService().CreateExcel(ResultWithActivity(), directory);
            using var workbook = new XLWorkbook(path);

            var sheet = workbook.Worksheet("Действия на устройствах");
            var values = sheet.CellsUsed().Select(x => x.GetString()).ToArray();
            Assert.Contains(values, x => x.Contains(@"E:\Фото\Отпуск"));
            Assert.Contains(values, x => x.Contains("Почему отнесено к устройству"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Печатный отчёт строится другим движком, чем HTML, поэтому его надо
    /// собрать по-настоящему: разметка, которая компилируется, может падать
    /// при выводе.
    /// </summary>
    [Fact]
    public void Full_pdf_report_is_generated_with_the_activity_section()
    {
        var directory = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var path = new ReportService().CreatePdf(ResultWithActivity(), directory);

            Assert.True(File.Exists(path));
            Assert.True(new FileInfo(path).Length > 1000);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Brief_pdf_report_is_generated_with_the_activity_verdict()
    {
        var directory = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var path = new ReportService().CreateBriefPdf(ResultWithActivity(), directory);

            Assert.True(File.Exists(path));
            Assert.True(new FileInfo(path).Length > 1000);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static AuditResult ResultWithActivity()
    {
        var device = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer\4C530001120523118563&0",
            CanonicalDeviceId = "4C530001120523118563",
            IsCanonicalPrimary = true,
            Serial = "4C530001120523118563",
            FriendlyName = "SanDisk Cruzer",
            VisualCategory = "RealUsb",
            DriveLetters = "E:",
            Volumes = [new VolumeIdentity { DriveLetter = "E:", VolumeSerialNumber = "D16CE60D" }]
        };
        DeviceTransportClassifier.Classify(device);

        var result = new AuditResult
        {
            ComputerName = "Тестовый ПК",
            StartedAtUtc = Moment,
            FinishedAtUtc = Moment.AddMinutes(2)
        };
        result.Devices.Add(device);
        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = Moment,
            Source = "Live HKU SID_Classes Shellbags",
            EvidenceCategory = "User activity",
            DeviceHint = @"E:\Фото\Отпуск",
            Summary = @"Live HKU SID_Classes Shellbags: E:\Фото\Отпуск",
            ResolvedUserName = @"ПК\ivanov"
        });

        return result;
    }
}
