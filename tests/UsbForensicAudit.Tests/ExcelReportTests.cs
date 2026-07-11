using ClosedXML.Excel;
using System.IO;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class ExcelReportTests
{
    [Fact]
    public void Full_and_brief_pdf_reports_are_generated_as_valid_pdf_files()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var service = new ReportService();
            var fullPath = service.CreatePdf(CreateResult(), directory, CreateExternalSnapshot());
            var briefPath = service.CreateBriefPdf(CreateResult(), directory);

            foreach (var path in new[] { fullPath, briefPath })
            {
                Assert.True(File.Exists(path));
                Assert.True(new FileInfo(path).Length > 1000);
                Assert.Equal("%PDF", System.Text.Encoding.ASCII.GetString(File.ReadAllBytes(path), 0, 4));
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Full_excel_report_is_valid_structured_and_readable()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var result = CreateResult();
            result.Devices[0].UserMeaning = string.Join(
                " ",
                Enumerable.Repeat("Подробное forensic-описание USB-устройства должно оставаться внутри ячейки.", 12));
            var path = new ReportService().CreateExcel(result, directory, CreateExternalSnapshot());

            Assert.True(File.Exists(path));
            using var workbook = new XLWorkbook(path);

            Assert.Equal(
                new[]
                {
                    "Сводка",
                    "USB устройства",
                    "Доказательства",
                    "Следы очистки",
                    "Предупреждения",
                    "Сторонние утилиты"
                },
                workbook.Worksheets.Select(x => x.Name).ToArray());

            var summary = workbook.Worksheet("Сводка");
            Assert.Contains("Полный отчёт", summary.Cell("A1").GetString());
            Assert.Equal("Тестовый ПК", summary.Cell("B5").GetString());
            var scopeRow = summary.Column(1).CellsUsed()
                .First(c => c.GetString() == "Область отчёта")
                .Address.RowNumber;
            Assert.Contains("USB", summary.Cell(scopeRow, 2).GetString());
            Assert.Contains(summary.Column(1).CellsUsed(),
                c => c.GetString() == "Покрытие источников");
            Assert.Contains(summary.Column(1).CellsUsed(),
                c => c.GetString() == "TestCollector");

            var devices = workbook.Worksheet("USB устройства");
            Assert.Equal("Категория", devices.Cell("A4").GetString());
            Assert.Equal("Тестовая флешка", devices.Cell("B5").GetString());
            Assert.True(devices.AutoFilter.IsEnabled);
            Assert.True(devices.Cell("C5").Style.Alignment.WrapText);
            Assert.True(devices.Column(2).Width >= 30);
            Assert.InRange(devices.Row(5).Height, 22, 108);
            Assert.Equal(4, devices.SheetView.SplitRow);
            Assert.Equal(1, devices.SheetView.SplitColumn);
            Assert.Equal(XLPageOrientation.Landscape, devices.PageSetup.PageOrientation);
            Assert.InRange(devices.SheetView.ZoomScale, 70, 90);

            var evidence = workbook.Worksheet("Доказательства");
            Assert.Equal("Подключение USB", evidence.Cell("B5").GetString());
            Assert.Equal("Direct", evidence.Cell("D5").GetString());
            Assert.Equal("High", evidence.Cell("E5").GetString());

            var cleanup = workbook.Worksheet("Следы очистки");
            Assert.Equal("Высокий", cleanup.Cell("C5").GetString());

            var external = workbook.Worksheet("Сторонние утилиты");
            Assert.Equal("USBDeview", external.Cell("B5").GetString());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Brief_excel_report_contains_all_usb_devices_and_stable_layout()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var result = CreateResult();
            for (var index = 0; index < 30; index++)
            {
                result.Devices.Add(new UsbDeviceRecord
                {
                    VisualCategory = "RealUsb",
                    UserMeaning = "Дополнительное USB-устройство",
                    DeviceInstanceId = $@"USB\VID_1234&PID_5678\SERIAL_{index:00}",
                    FriendlyName = $"USB устройство {index:00}",
                    Serial = $"SERIAL_{index:00}"
                });
            }

            var path = new ReportService().CreateBriefExcel(result, directory);

            Assert.True(File.Exists(path));
            using var workbook = new XLWorkbook(path);

            Assert.Equal(
                new[] { "Сводка", "Инциденты", "Все USB устройства", "Предупреждения" },
                workbook.Worksheets.Select(x => x.Name).ToArray());
            Assert.Contains("Сводный отчёт", workbook.Worksheet("Сводка").Cell("A1").GetString());
            var devices = workbook.Worksheet("Все USB устройства");
            Assert.Equal(31, devices.Column(2).CellsUsed().Count() - 1);
            Assert.Contains(devices.Column(2).CellsUsed(), cell => cell.GetString() == "Тестовая флешка");
            Assert.Contains(devices.Column(2).CellsUsed(), cell => cell.GetString() == "USB устройство 29");
            Assert.Equal(4, devices.SheetView.SplitRow);
            Assert.Equal(1, devices.SheetView.SplitColumn);
            Assert.True(workbook.Worksheet("Инциденты").AutoFilter.IsEnabled);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static AuditResult CreateResult()
    {
        var result = new AuditResult
        {
            ComputerName = "Тестовый ПК",
            UserName = "Аналитик",
            WindowsVersion = "Windows 11",
            StartedAtUtc = new DateTimeOffset(2026, 7, 11, 6, 0, 0, TimeSpan.Zero),
            FinishedAtUtc = new DateTimeOffset(2026, 7, 11, 6, 1, 30, TimeSpan.Zero),
            IsAdministrator = true
        };
        result.Coverage = new ScanCoverageReport
        {
            CanonicalDeviceCount = 1,
            CanonicalDevicesWithExactDates = 1,
            Sources =
            [
                new SourceCoverage
                {
                    Source = "TestCollector",
                    Status = "Complete",
                    Count = 1
                }
            ]
        };

        result.Devices.Add(new UsbDeviceRecord
        {
            VisualCategory = "RealUsb",
            UserMeaning = "Реальное USB-устройство",
            DeviceInstanceId = @"USB\VID_0951&PID_1666\SERIAL",
            FriendlyName = "Тестовая флешка",
            Manufacturer = "Kingston",
            Product = "DataTraveler",
            Vid = "0951",
            Pid = "1666",
            Serial = "SERIAL",
            FirstConnectedUtc = result.StartedAtUtc,
            LastSeenUtc = result.FinishedAtUtc,
            ConnectionDisplayKind = "ExactEvent",
            DisconnectDisplayKind = "ConnectedNow",
            IsCurrentlyConnected = true,
            DateConfidence = "Точная дата из журнала Windows."
        });

        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = result.StartedAtUtc,
            EvidenceCategory = "Подключение USB",
            Source = "EventLog: System",
            EventId = "2003",
            EvidenceStrength = "Direct",
            Confidence = "High",
            Provenance = "Windows Event Log: channel=System; record=42",
            DeviceHint = @"USB\VID_0951&PID_1666\SERIAL",
            UserExplanation = "Windows зафиксировала подключение устройства.",
            Summary = "Устройство подключено."
        });

        result.CleanupFindings.Add(new CleanupFinding
        {
            TimestampUtc = result.FinishedAtUtc,
            Assessment = "Suspicious",
            Severity = "High",
            Confidence = "Probable",
            ActionKind = "RegistryCleanup",
            PossibleTool = "USB Oblivion",
            Finding = "Тестовый признак очистки",
            Details = "Требуется ручная проверка."
        });

        result.SourceWarnings.Add("Тестовый источник недоступен.");
        return result;
    }

    private static ExternalUtilityReportSnapshot CreateExternalSnapshot()
    {
        var snapshot = new ExternalUtilityReportSnapshot
        {
            CapturedAtUtc = new DateTimeOffset(2026, 7, 11, 6, 2, 0, TimeSpan.Zero),
            UtilityName = "USBDeview"
        };
        snapshot.Rows.Add(new ExternalUtilityRow
        {
            SectionTitle = "Устройства",
            UtilityName = "USBDeview",
            PrimaryText = "Тестовая флешка",
            Values = new Dictionary<string, string> { ["Device Name"] = "Тестовая флешка" },
            VidPidText = "VID 0951 / PID 1666",
            VendorProductText = "Kingston / DataTraveler",
            VerdictDisplayText = "Подтверждено",
            AnalysisText = "Совпадает с данными Windows."
        });
        return snapshot;
    }

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "UsbForensicAudit.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
