using System.IO;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class ExternalUtilityCatalogTests
{
    [Theory]
    [InlineData("USBDeview.exe", "usbdeview")]
    [InlineData("USBDeview", "usbdeview")]
    [InlineData("USBDetector.exe", "usbdetector")]
    [InlineData("USBOblivion64.exe", "usboblivion")]
    [InlineData("USBOblivion64", "usboblivion")]
    public void MatchProcess_recognizes_known_utilities(string processName, string expectedId)
    {
        var match = ExternalUtilityCatalog.MatchProcess(processName);
        Assert.NotNull(match);
        Assert.Equal(expectedId, match!.Id);
    }

    [Theory]
    [InlineData("notepad.exe")]
    [InlineData("explorer.exe")]
    public void MatchProcess_ignores_unrelated_processes(string processName)
    {
        Assert.Null(ExternalUtilityCatalog.MatchProcess(processName));
    }
}

public class ExternalUtilityWindowCaptureServiceTests
{
    [Fact]
    public void Capture_rejects_usb_oblivion_without_touching_process()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            ExternalUtilityWindowCaptureService.Capture(new RunningExternalUtility
            {
                UtilityId = "usboblivion",
                DisplayName = "USB Oblivion",
                ProcessId = Environment.ProcessId,
                ProcessName = "USBOblivion64",
                MainWindowTitle = "USBOblivion",
                HasMainWindow = true
            }));

        Assert.Contains("не показывает таблицу", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}

public class ExternalUtilityRowFormatterTests
{
    [Fact]
    public void FormattedDetailsText_uses_line_breaks()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Тест",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string>
            {
                ["VID"] = "0E0F",
                ["PID"] = "0003",
                ["Производитель"] = "VMware, Inc.",
                ["Модель"] = "Virtual USB",
                ["Первое подключение"] = "10.10.2023 00:03"
            },
            PrimaryText = "VMware"
        };

        var formatted = row.FormattedDetailsText;
        Assert.Contains(Environment.NewLine, formatted);
        Assert.Contains("Производитель: VMware, Inc.", formatted);
        Assert.Contains("Первое подключение: 10.10.2023 00:03", formatted);
    }

    [Fact]
    public void KeyFieldsText_uses_vid_pid_and_real_date()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Другие следы подключения устройств",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string>
            {
                ["VID"] = "0E0F",
                ["PID"] = "0003",
                ["Производитель"] = "VMware, Inc.",
                ["Модель"] = "Virtual Mouse",
                ["Первое подключение"] = "10.10.2023 00:03"
            },
            PrimaryText = "0E0F"
        };

        var summary = row.KeyFieldsText;
        Assert.Contains("VID/PID: 0E0F/0003", summary);
        Assert.Contains("Произв.: VMware, Inc.", summary);
        Assert.Contains("Модель: Virtual Mouse", summary);
        Assert.Contains("Дата: 10.10.2023 00:03", summary);
        Assert.DoesNotContain("Дата: 0003", summary);
    }

    [Fact]
    public void CopyText_uses_tab_separators()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Тест",
            UtilityName = "USBDeview",
            Values = new Dictionary<string, string>
            {
                ["Device Name"] = "Kingston",
                ["Description"] = "USB Disk"
            },
            PrimaryText = "Kingston"
        };

        Assert.Equal("Kingston\tUSB Disk", row.CopyText);
    }
}

public class ExternalUtilityColumnNormalizerTests
{
    [Fact]
    public void MapRowValues_fixes_shifted_usbdetector_columns()
    {
        var values = ExternalUtilityColumnNormalizer.MapRowValues(
            ["Производитель", "Модель", "Установка", "Первое подключение"],
            ["0E0F", "VMware, Inc.", "0003", "10.10.2023 00:03"]);

        Assert.Equal("0E0F", values["VID"]);
        Assert.Equal("VMware, Inc.", values["Производитель"]);
        Assert.Equal("0003", values["PID"]);
        Assert.Equal("10.10.2023 00:03", values["Первое подключение"]);
    }

    [Fact]
    public void NormalizeHeaderName_expands_truncated_first_connection()
    {
        Assert.Equal("Первое подключение", ExternalUtilityColumnNormalizer.NormalizeHeaderName("Первое подключ..."));
    }
}

public class ExternalUtilityManualParserTests
{
    [Fact]
    public void Parse_splits_tab_separated_values()
    {
        var row = ExternalUtilityManualParser.Parse("Kingston\tVID_0951\tPID_1666\t01.01.1970");

        Assert.Equal(4, row.Values.Count);
        Assert.Equal("Kingston", row.Values["Поле 1"]);
        Assert.Equal("Kingston", row.PrimaryText);
    }

    [Fact]
    public void Parse_splits_pipe_separated_values()
    {
        var row = ExternalUtilityManualParser.Parse("VMware | VID_0E0F | PID_0003 | 01.01.1970 03:00");

        Assert.Equal(4, row.Values.Count);
        Assert.Equal("VMware", row.Values["Поле 1"]);
        Assert.Equal("VMware", row.PrimaryText);
    }

    [Fact]
    public void Parse_keeps_single_value_as_text()
    {
        var row = ExternalUtilityManualParser.Parse("Single line without separators");

        Assert.Equal("Single line without separators", row.Values["Текст"]);
        Assert.Equal("Ручной ввод", row.SectionTitle);
    }
}

public class ExternalUtilityHistoryServiceTests
{
    [Fact]
    public void CollectFromAudit_returns_usb_utilities_only()
    {
        var result = new AuditResult();
        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            EventId = "PROCESS_HINT",
            Source = "Prefetch",
            Summary = "USBDeview.exe",
            RawText = "C:\\Tools\\USBDeview.exe"
        });
        result.Evidence.Add(new EvidenceRecord
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            EventId = "PROCESS_HINT",
            Source = "Prefetch",
            Summary = "notepad.exe",
            RawText = "C:\\Windows\\notepad.exe"
        });

        var launches = ExternalUtilityHistoryService.CollectFromAudit(result);
        Assert.Single(launches);
        Assert.Contains("USBDeview", launches[0].ToolName, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CollectFromAudit_returns_empty_for_null()
    {
        Assert.Empty(ExternalUtilityHistoryService.CollectFromAudit(null));
    }
}

public class ExternalUtilitySnapshotStorageTests
{
    [Fact]
    public void Save_and_load_roundtrip()
    {
        var dir = Path.Combine(Path.GetTempPath(), "UsbForensicAuditTests", Guid.NewGuid().ToString("N"));
        var snapshot = new ExternalUtilityReportSnapshot
        {
            CapturedAtUtc = DateTimeOffset.UtcNow,
            UtilityName = "USBDetector"
        };
        snapshot.Rows.Add(new ExternalUtilityRow
        {
            SectionTitle = "Основной список",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["UID"] = "VID_1234&PID_5678" },
            PrimaryText = "Test device",
            AnalysisText = "Analysis"
        });
        snapshot.HistoricalLaunches.Add(new HistoricalUtilityLaunch
        {
            ToolName = "USBDeview",
            Source = "Prefetch",
            TimestampUtc = DateTimeOffset.UtcNow,
            Summary = "Launch"
        });

        ExternalUtilitySnapshotStorage.Save(dir, snapshot);
        var loaded = ExternalUtilitySnapshotStorage.Load(dir);

        Assert.NotNull(loaded);
        Assert.Equal("USBDetector", loaded!.UtilityName);
        Assert.Single(loaded.Rows);
        Assert.Equal("Test device", loaded.Rows[0].PrimaryText);
        Assert.Single(loaded.HistoricalLaunches);

        Directory.Delete(dir, true);
    }
}

public class ExternalUtilityRowExplainerTests
{
    [Fact]
    public void Explain_finds_matching_device_in_audit()
    {
        var audit = new AuditResult
        {
            OsInstalledAtUtc = DateTimeOffset.Parse("2024-01-01T00:00:00+03:00")
        };
        audit.Devices.Add(new UsbDeviceRecord
        {
            FriendlyName = "VMware USB Device",
            Vid = "0E0F",
            Pid = "0003",
            DeviceInstanceId = "USB\\VID_0E0F&PID_0003\\serial",
            Source = "Registry",
            DeviceType = "UsbDevice"
        });

        var row = new ExternalUtilityRow
        {
            SectionTitle = "Другие следы подключения устройств",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["UID"] = "VID_0E0F&PID_0003 VMware" },
            PrimaryText = "VMware"
        };

        var text = ExternalUtilityRowExplainer.Explain(row, audit);
        Assert.Contains("ГДЕ ИСКАЛИ В WINDOWS", text);
        Assert.Contains("ФОРМУЛИРОВКА ПО ДЕЛУ", text);
        Assert.Contains("VMware USB Device", text);
    }

    [Fact]
    public void Assess_marks_other_traces_as_indirect_without_audit_match()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["UID"] = "VID_1234&PID_5678 VMware" },
            PrimaryText = "VMware"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, new AuditResult());
        Assert.Equal(ExternalUtilityVerdictLevel.Indirect, assessment.Level);
        Assert.Contains("косвен", assessment.VerdictTitle, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ГДЕ ИСКАЛИ В WINDOWS", assessment.SourceChecksText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ФОРМУЛИРОВКА ПО ДЕЛУ", assessment.FullExplanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Assess_marks_vmware_as_virtual()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["UID"] = "VID_0E0F&PID_0003" },
            PrimaryText = "VMware"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, null);
        Assert.Equal(ExternalUtilityVerdictLevel.Virtual, assessment.Level);
        Assert.Contains("VMware", assessment.ProbableOrigin, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("VMware, Inc.", assessment.Identifier.VendorLookup.VendorName!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Virtual Mouse", assessment.Identifier.VendorLookup.ProductName!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Assess_usbdeview_vendor_product_columns_confirms_audit_match()
    {
        var audit = new AuditResult();
        audit.Devices.Add(new UsbDeviceRecord
        {
            FriendlyName = "Kingston DataTraveler",
            Vid = "0951",
            Pid = "1666",
            DeviceInstanceId = "USB\\VID_0951&PID_1666\\001",
            Source = "Registry",
            DeviceType = "UsbDevice"
        });

        var row = new ExternalUtilityRow
        {
            SectionTitle = "Список устройств",
            UtilityName = "USBDeview",
            Values = new Dictionary<string, string>
            {
                ["Device Name"] = "Kingston DataTraveler",
                ["Vendor ID"] = "0951",
                ["Product ID"] = "1666"
            },
            PrimaryText = "Kingston DataTraveler"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, audit);
        Assert.Equal(ExternalUtilityVerdictLevel.Confirmed, assessment.Level);
        Assert.Contains("USB устройства", assessment.VerdictTitle, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("0951/1666", assessment.Identifier.VidPidText);
    }

    [Fact]
    public void Assess_usbdeview_match_wins_over_epoch_date()
    {
        var audit = new AuditResult();
        audit.Devices.Add(new UsbDeviceRecord
        {
            FriendlyName = "Test",
            Vid = "0951",
            Pid = "1666",
            DeviceInstanceId = "USB\\VID_0951&PID_1666\\x",
            Source = "Registry",
            DeviceType = "UsbDevice"
        });

        var row = new ExternalUtilityRow
        {
            SectionTitle = "Список устройств",
            UtilityName = "USBDeview",
            Values = new Dictionary<string, string>
            {
                ["Vendor ID"] = "0951",
                ["Product ID"] = "1666",
                ["Created Date"] = "01.01.1970 03:00:00"
            },
            PrimaryText = "Test"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, audit);
        Assert.Equal(ExternalUtilityVerdictLevel.Confirmed, assessment.Level);
    }

    [Fact]
    public void Assess_recognizes_bare_0E0F_primary_text_as_vmware()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string>(),
            PrimaryText = "0E0F"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, new AuditResult());
        Assert.Equal(ExternalUtilityVerdictLevel.Virtual, assessment.Level);
        Assert.Equal("0E0F", assessment.Identifier.Vid);
        Assert.Contains("VMware, Inc.", assessment.Identifier.VendorLookup.VendorName!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ФОРМУЛИРОВКА ПО СТРОКЕ", assessment.FullExplanation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("не физический накопитель", assessment.ReportConclusionRow, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("VMware", assessment.ReportConclusionCase, StringComparison.OrdinalIgnoreCase);
    }
}

public class ExternalUtilitySourceCorrelatorTests
{
    [Fact]
    public void Correlate_finds_audit_device_path()
    {
        var audit = new AuditResult();
        audit.Devices.Add(new UsbDeviceRecord
        {
            FriendlyName = "Kingston",
            Vid = "0951",
            Pid = "1666",
            DeviceInstanceId = @"USB\VID_0951&PID_1666\001",
            Source = "Registry: USB"
        });

        var identifier = ExternalUtilityIdentifierParser.Parse(new ExternalUtilityRow
        {
            Values = new Dictionary<string, string> { ["Vendor ID"] = "0951", ["Product ID"] = "1666" },
            PrimaryText = "Kingston",
            UtilityName = "USBDeview",
            SectionTitle = "Список устройств"
        });

        var hits = ExternalUtilitySourceCorrelator.Correlate(identifier, audit);
        Assert.Contains(hits, x => x.Found && x.RegistryPath.Contains("VID_0951", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void FormatSourceChecks_mentions_usbdetector_tracing()
    {
        var hits = new[]
        {
            new ExternalUtilitySourceHit
            {
                Title = "Enum\\USB",
                RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Enum\USB",
                Found = false,
                ResultText = "нет ключа"
            }
        };

        var text = ExternalUtilitySourceCorrelator.FormatSourceChecks(hits, isUsbDetector: true, isOtherTraces: true);
        Assert.Contains("USBDetector", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Procmon", text, StringComparison.OrdinalIgnoreCase);
    }
}

public class UsbVendorDatabaseTests
{
    [Fact]
    public void Lookup_resolves_vmware_vid_and_products()
    {
        var lookup = UsbVendorDatabase.Lookup("0E0F", "0003");
        Assert.Equal("VMware, Inc.", lookup.VendorName);
        Assert.Equal("Virtual Mouse", lookup.ProductName);
    }

    [Fact]
    public void IdentifierParser_recognizes_truncated_vid_in_primary_text()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string>(),
            PrimaryText = "0E0F"
        };

        var info = ExternalUtilityIdentifierParser.Parse(row);
        Assert.Equal("0E0F", info.Vid);
        Assert.Contains("Обрезан", info.ParseMethod, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("VMware, Inc.", info.VendorLookup.VendorName);
    }

    [Fact]
    public void Parse_reads_usbdeview_vendor_and_product_columns()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Список устройств",
            UtilityName = "USBDeview",
            Values = new Dictionary<string, string>
            {
                ["Device Name"] = "Kingston",
                ["Vendor ID"] = "0951",
                ["Product ID"] = "1666"
            },
            PrimaryText = "Kingston"
        };

        var info = ExternalUtilityIdentifierParser.Parse(row);
        Assert.Equal("0951", info.Vid);
        Assert.Equal("1666", info.Pid);
        Assert.Contains("USBDeview", info.ParseMethod, StringComparison.OrdinalIgnoreCase);
    }
}

public class ProcessBitnessHelperTests
{
    [Fact]
    public void RequiresUiAutomation_is_true_for_current_process_when_wow64()
    {
        if (!Environment.Is64BitProcess)
        {
            return;
        }

        using var process = System.Diagnostics.Process.GetCurrentProcess();
        var requires = ProcessBitnessHelper.RequiresUiAutomationForWindowMessages(process.Id);
        Assert.False(requires);
    }
}
