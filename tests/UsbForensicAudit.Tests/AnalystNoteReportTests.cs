using System.IO;
using ClosedXML.Excel;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Аналитическая записка в Excel: листы, таблицы, предупреждения и хронология
/// строятся из одного и того же содержимого AnalystNoteContent.
/// </summary>
public sealed class AnalystNoteReportTests
{
    private static readonly DateTimeOffset OsInstalled = DateTimeOffset.Parse("2024-06-01T00:00:00Z");
    private static readonly DateTimeOffset Started = DateTimeOffset.Parse("2026-03-01T08:00:00Z");

    [Fact]
    public void Analyst_note_excel_contains_all_sheets_and_key_sections()
    {
        var result = BuildRichResult();
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-note-{Guid.NewGuid():N}");
        try
        {
            var path = new ReportService().CreateAnalystNoteExcel(result, directory);
            Assert.True(File.Exists(path));

            using var workbook = new XLWorkbook(path);
            foreach (var name in new[] { "Записка", "Устройства", "Сеть", "Действия пользователя", "Хронология" })
            {
                Assert.True(workbook.Worksheets.Contains(name), $"нет листа {name}");
            }

            var summary = workbook.Worksheet("Записка");
            Assert.Contains("Аналитическая записка", summary.Cell(1, 1).GetString());
            var summaryText = SheetText(summary);
            Assert.Contains("Объект аудита", summaryText);
            Assert.Contains("Выводы", summaryText);

            var devices = workbook.Worksheet("Устройства");
            var devicesText = SheetText(devices);
            Assert.Contains("SanDisk", devicesText);
            // Совпадающие VID/PID у двух устройств — предупреждение о клоне.
            Assert.Contains("возможен клон или кастомная прошивка", devicesText);

            var network = workbook.Worksheet("Сеть");
            var networkText = SheetText(network);
            Assert.Contains("Сетевые подключения", networkText);
            Assert.Contains("Office-WiFi", networkText);
            Assert.Contains("Сетевые сеансы", networkText);

            var actions = workbook.Worksheet("Действия пользователя");
            var actionsText = SheetText(actions);
            Assert.Contains(@"E:\Фото\Отпуск", actionsText);

            var chronology = workbook.Worksheet("Хронология");
            var chronologyText = SheetText(chronology);
            Assert.Contains("Установка Windows.", chronologyText);
            Assert.Contains(AnalystNoteContent.PreInstallCaveat, chronologyText);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, true);
            }
        }
    }

    [Fact]
    public void Analyst_note_excel_survives_empty_audit_result()
    {
        var result = new AuditResult
        {
            StartedAtUtc = Started,
            FinishedAtUtc = Started.AddMinutes(1)
        };
        var path = Path.Combine(Path.GetTempPath(), $"ufa-note-empty-{Guid.NewGuid():N}.xlsx");
        try
        {
            AnalystNoteExcelReport.Generate(path, ForensicReportContext.Create(result));
            using var workbook = new XLWorkbook(path);
            Assert.Contains("Подключаемых устройств в собранных данных не найдено.",
                SheetText(workbook.Worksheet("Устройства")));
            Assert.Contains("Сетевых связей в собранных данных не найдено.",
                SheetText(workbook.Worksheet("Сеть")));
            Assert.Contains("Следов работы с файлами на устройствах не найдено.",
                SheetText(workbook.Worksheet("Действия пользователя")));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void Chronology_is_ordered_and_marks_stamps_older_than_os_install()
    {
        var context = ForensicReportContext.Create(BuildRichResult());

        var chronology = AnalystNoteContent.BuildChronology(context);

        Assert.NotEmpty(chronology);
        var ordered = chronology.Select(x => x.At).ToArray();
        Assert.Equal(ordered.OrderBy(x => x).ToArray(), ordered);
        Assert.Contains(chronology, x => x.Text == "Установка Windows.");
        // Штамп 2020 года старше установки ОС 2024 года — обязан быть помечен.
        Assert.Contains(chronology, x => x.IsOlderThanOsInstall);
        // Само событие установки ОС пометки не получает.
        Assert.DoesNotContain(chronology, x => x.Text == "Установка Windows." && x.IsOlderThanOsInstall);
        Assert.Contains(chronology, x => x.Text.Contains("первое подключение"));
        Assert.Contains(chronology, x => x.Text.Contains("Office-WiFi"));
        Assert.Contains(chronology, x => x.Text.Contains("Признак очистки"));
    }

    [Fact]
    public void Shared_vid_pid_warning_names_both_devices()
    {
        var context = ForensicReportContext.Create(BuildRichResult());

        var warnings = AnalystNoteContent.SharedVidPidWarnings(context);

        var warning = Assert.Single(warnings);
        Assert.Contains("0951:1666", warning, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("возможен клон или кастомная прошивка", warning);
    }

    [Fact]
    public void Device_detail_line_lists_volumes_and_activity_count()
    {
        var context = ForensicReportContext.Create(BuildRichResult());
        var device = context.ListedDevices.Single(x => x.Serial == "4C530001120523118563");

        var line = AnalystNoteContent.DeviceDetailLine(context, device);

        Assert.Contains("тома E:", line);
        Assert.Contains("действий с файлами:", line);
    }

    [Fact]
    public void Device_without_activity_gets_honest_detail_line()
    {
        var result = BuildRichResult();
        var context = ForensicReportContext.Create(result);
        var device = context.ListedDevices.First(x => x.Serial == "SERIAL-B");

        var line = AnalystNoteContent.DeviceDetailLine(context, device);

        Assert.Contains("следов работы с файлами не найдено", line);
    }

    private static string SheetText(IXLWorksheet sheet) =>
        string.Join("\n", sheet.CellsUsed().Select(x => x.GetString()));

    /// <summary>
    /// Результат аудита со всем, о чём рассказывает записка: устройства с
    /// совпадающими VID/PID, флешка с активностью, сеть Wi-Fi с сеансами,
    /// признак очистки и штамп старше установки ОС.
    /// </summary>
    private static AuditResult BuildRichResult()
    {
        var result = new AuditResult
        {
            StartedAtUtc = Started,
            FinishedAtUtc = Started.AddMinutes(2),
            OsInstalledAtUtc = OsInstalled,
            IsAdministrator = true
        };

        result.Devices.AddRange(
        [
            new UsbDeviceRecord
            {
                VisualCategory = "RealUsb",
                DeviceType = "USB",
                Source = "Registry: USB",
                DeviceInstanceId = @"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer\4C530001120523118563&0",
                FriendlyName = "SanDisk Cruzer",
                Vid = "0951",
                Pid = "1666",
                Serial = "4C530001120523118563",
                DeviceKind = DeviceKindResolver.Storage,
                DriveLetters = "E:",
                Volumes = [new VolumeIdentity { DriveLetter = "E:", VolumeSerialNumber = "D16CE60D" }],
                FirstConnectedUtc = Started.AddMinutes(-30),
                LastSeenUtc = Started.AddMinutes(-5),
                ConnectionDisplayKind = "ExactEvent"
            },
            new UsbDeviceRecord
            {
                VisualCategory = "RealUsb",
                DeviceType = "USB",
                Source = "Registry: USB",
                DeviceInstanceId = @"USB\VID_0951&PID_1666\SERIAL-B",
                Vid = "0951",
                Pid = "1666",
                Serial = "SERIAL-B",
                Manufacturer = "Kingston"
            }
        ]);

        // Действие на устройстве: папка открыта на диске E, штамп 2020 года —
        // старше установки ОС, чтобы сработала пометка в хронологии.
        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = DateTimeOffset.Parse("2020-05-05T10:00:00Z"),
            Source = "Live HKU SID_Classes Shellbags",
            DeviceHint = @"E:\Фото\Отпуск",
            Summary = @"Live HKU SID_Classes Shellbags: E:\Фото\Отпуск",
            RegistryLastWriteUtc = DateTimeOffset.Parse("2020-05-05T10:00:00Z")
        });

        result.NetworkConnections.Add(new NetworkConnectionRecord
        {
            Kind = NetworkConnectionKind.WiFi,
            Name = "Office-WiFi",
            Address = "AA:BB:CC:DD:EE:FF",
            FirstSeenUtc = Started.AddDays(-2),
            LastSeenUtc = Started.AddHours(-1),
            Direction = "Outbound",
            Sessions =
            [
                new NetworkSession
                {
                    StartedUtc = Started.AddHours(-3),
                    EndedUtc = Started.AddHours(-1),
                    Outcome = "Connected"
                },
                new NetworkSession
                {
                    StartedUtc = Started.AddDays(-2),
                    Outcome = "Rejected",
                    IsMoment = true
                }
            ]
        });

        result.CleanupFindings.Add(new CleanupFinding
        {
            TimestampUtc = Started.AddMinutes(-10),
            Severity = "High",
            Assessment = "Suspicious",
            Area = "SetupAPI",
            Finding = "Журнал событий очищен",
            ActionKind = "LogClearing"
        });

        return result;
    }
}
