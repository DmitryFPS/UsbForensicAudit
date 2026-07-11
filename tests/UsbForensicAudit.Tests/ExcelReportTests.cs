using ClosedXML.Excel;
using System.IO;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class ExcelReportTests
{
    [Fact]
    public void Full_excel_report_is_valid_structured_and_readable()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var path = new ReportService().CreateExcel(CreateResult(), directory, CreateExternalSnapshot());

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

            var devices = workbook.Worksheet("USB устройства");
            Assert.Equal("Категория", devices.Cell("A4").GetString());
            Assert.Equal("Тестовая флешка", devices.Cell("B5").GetString());
            Assert.True(devices.AutoFilter.IsEnabled);
            Assert.True(devices.Cell("C5").Style.Alignment.WrapText);
            Assert.True(devices.Column(2).Width >= 30);

            var evidence = workbook.Worksheet("Доказательства");
            Assert.Equal("Подключение USB", evidence.Cell("B5").GetString());

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
    public void Brief_excel_report_contains_only_human_focused_sections()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var path = new ReportService().CreateBriefExcel(CreateResult(), directory);

            Assert.True(File.Exists(path));
            using var workbook = new XLWorkbook(path);

            Assert.Equal(
                new[] { "Сводка", "Инциденты", "Значимые USB", "Предупреждения" },
                workbook.Worksheets.Select(x => x.Name).ToArray());
            Assert.Contains("Сводный отчёт", workbook.Worksheet("Сводка").Cell("A1").GetString());
            Assert.Equal("Тестовая флешка", workbook.Worksheet("Значимые USB").Cell("B5").GetString());
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
