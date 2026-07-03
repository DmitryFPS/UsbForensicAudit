using System.IO;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class ExternalUtilityCoverageBoostTests
{
    [Fact]
    public void Parse_reads_instance_id_column()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Список",
            UtilityName = "USBDeview",
            PrimaryText = "Device",
            Values = new Dictionary<string, string>
            {
                ["Instance ID"] = @"USB\VID_0951&PID_1666\001"
            }
        };

        var info = ExternalUtilityIdentifierParser.Parse(row);
        Assert.Equal("0951", info.Vid);
        Assert.Equal("1666", info.Pid);
        Assert.Contains("Instance", info.ParseMethod, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_reads_standalone_vid_in_combined_text()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Список",
            UtilityName = "USBDeview",
            PrimaryText = "Kingston VID_0951 only",
            Values = new Dictionary<string, string>()
        };

        var info = ExternalUtilityIdentifierParser.Parse(row);
        Assert.Equal("0951", info.Vid);
        Assert.Null(info.Pid);
    }

    [Fact]
    public void Correlate_includes_audit_evidence_for_mountpoints()
    {
        var audit = new AuditResult();
        audit.Evidence.Add(new EvidenceRecord
        {
            Source = "Hive: MountPoints2",
            Summary = "Mount for VID_0951&PID_1666",
            RawText = "VID_0951&PID_1666"
        });

        var identifier = ExternalUtilityIdentifierParser.Parse(new ExternalUtilityRow
        {
            Values = new Dictionary<string, string> { ["VID"] = "0951", ["PID"] = "1666" },
            PrimaryText = "Kingston",
            UtilityName = "USBDeview",
            SectionTitle = "Список"
        });

        var hits = ExternalUtilitySourceCorrelator.Correlate(identifier, audit);
        Assert.Contains(hits, h => h.Found && h.Title.Contains("MRU", StringComparison.OrdinalIgnoreCase) || h.Title.Contains("Mount", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void FormatSourceChecks_other_traces_with_direct_procmon()
    {
        var hits = new[]
        {
            new ExternalUtilitySourceHit
            {
                Title = "Procmon: Enum\\USBSTOR",
                RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_Kingston",
                Found = true,
                ResultText = "RegQueryValue → прямой ключ реестра USB",
                IsProcmonEvidence = true,
                EvidenceRank = 300
            }
        };

        var text = ExternalUtilitySourceCorrelator.FormatSourceChecks(hits, isUsbDetector: true, isOtherTraces: true);
        Assert.Contains("PROCMON", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("прямой ключ", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Assess_marks_epoch_date_in_other_traces()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["Первое подключение"] = "01.01.1970 03:00:00" },
            PrimaryText = "Unknown"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, new AuditResult());
        Assert.Contains("1970", assessment.UsbDetectorNote, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Assess_marks_date_before_os_install()
    {
        var audit = new AuditResult { OsInstalledAtUtc = DateTimeOffset.Parse("2024-01-01T00:00:00+03:00") };
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Основной список (реестр)",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["Установка"] = "01.06.2023 00:00" },
            PrimaryText = "Old"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, audit);
        Assert.Contains("установк", assessment.FullExplanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FormattedDetailsText_orders_known_fields()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Тест",
            UtilityName = "USBDeview",
            PrimaryText = "Kingston",
            Values = new Dictionary<string, string>
            {
                ["Device Name"] = "Kingston",
                ["Serial Number"] = "001",
                ["Vendor ID"] = "0951"
            }
        };

        var text = ExternalUtilityRowFormatter.FormattedDetailsText(row);
        Assert.Contains("Serial Number", text);
        Assert.Contains("0951", text);
    }

    [Fact]
    public void CopyTextWithHeaders_includes_header_row()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Тест",
            UtilityName = "USBDeview",
            PrimaryText = "Kingston",
            Values = new Dictionary<string, string> { ["Device Name"] = "Kingston", ["Description"] = "Disk" }
        };

        var text = ExternalUtilityRowFormatter.CopyTextWithHeaders(row);
        Assert.Equal("Kingston\tDisk", text);
    }

    [Fact]
    public void ParseFile_handles_quoted_csv_fields()
    {
        var path = Path.Combine(Path.GetTempPath(), $"procmon-{Guid.NewGuid():N}.csv");
        File.WriteAllText(path,
            """
            "Time of Day","Process Name","PID","Operation","Path","Result","Detail"
            "12:00:00.0000000","USBDetector.exe","100","RegOpenKey","HKLM\SYSTEM\MountedDevices","SUCCESS",""
            """,
            Encoding.UTF8);

        var events = ProcmonCsvParser.ParseFile(path);
        Assert.Single(events);
        Assert.Equal("USBDetector.exe", events[0].ProcessName);
    }

    [Fact]
    public void MapRowValues_remaps_shifted_usbdetector_row()
    {
        var values = ExternalUtilityColumnNormalizer.MapRowValues(
            ["VID", "Производитель", "PID", "Модель", "Первое подключение"],
            ["0E0F", "VMware, Inc.", "0003", "Virtual Mouse", "10.10.2023"]);

        Assert.Equal("0E0F", values["VID"]);
        Assert.Equal("0003", values["PID"]);
        Assert.Equal("VMware, Inc.", values["Производитель"]);
    }

    [Fact]
    public void Assess_probable_when_audit_matches_other_traces()
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

        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["VID"] = "0951", ["PID"] = "1666" },
            PrimaryText = "Kingston"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, audit);
        Assert.Equal(ExternalUtilityVerdictLevel.Probable, assessment.Level);
    }

    [Fact]
    public void Assess_not_found_for_unknown_vid_in_usbdeview()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Список устройств",
            UtilityName = "USBDeview",
            Values = new Dictionary<string, string> { ["Device Name"] = "Mystery" },
            PrimaryText = "Mystery"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, new AuditResult());
        Assert.Equal(ExternalUtilityVerdictLevel.NotFound, assessment.Level);
    }

    [Fact]
    public void Correlate_mounted_devices_audit_hit()
    {
        var audit = new AuditResult();
        audit.Devices.Add(new UsbDeviceRecord
        {
            FriendlyName = "Volume",
            Vid = "0951",
            Pid = "1666",
            DeviceInstanceId = "0951-1666",
            Source = "MountedDevices"
        });

        var identifier = ExternalUtilityIdentifierParser.Parse(new ExternalUtilityRow
        {
            Values = new Dictionary<string, string> { ["VID"] = "0951", ["PID"] = "1666" },
            PrimaryText = "Kingston",
            UtilityName = "USBDeview",
            SectionTitle = "Список"
        });

        var hits = ExternalUtilitySourceCorrelator.Correlate(identifier, audit);
        Assert.Contains(hits, h => h.Title.Contains("MountedDevices", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Assess_date_artifact_for_epoch_in_main_section()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = "Основной список (реестр)",
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["Установка"] = "01.01.1970 03:00:00", ["VID"] = "1234", ["PID"] = "5678" },
            PrimaryText = "Device"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, new AuditResult());
        Assert.Equal(ExternalUtilityVerdictLevel.DateArtifact, assessment.Level);
    }

    [Fact]
    public void Assess_indirect_other_traces_without_vid_match()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["VID"] = "ABCD", ["PID"] = "0001" },
            PrimaryText = "Unknown vendor"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, new AuditResult());
        Assert.Equal(ExternalUtilityVerdictLevel.Indirect, assessment.Level);
    }

    [Fact]
    public void Assess_origin_mentions_mounted_for_mount_text()
    {
        var row = new ExternalUtilityRow
        {
            SectionTitle = ExternalUtilitySectionCatalog.OtherTracesSection,
            UtilityName = "USBDetector",
            Values = new Dictionary<string, string> { ["UID"] = "MountedDevices hint" },
            PrimaryText = "Mount"
        };

        var assessment = ExternalUtilityRowExplainer.Assess(row, new AuditResult());
        Assert.Contains("MountedDevices", assessment.ProbableOrigin, StringComparison.OrdinalIgnoreCase);
    }
}

public class CleanerToolCatalogExtendedTests
{
    [Theory]
    [InlineData("ccleaner", "CCleaner")]
    [InlineData("bleachbit", "BleachBit")]
    [InlineData("privazer", "PrivaZer")]
    [InlineData("device cleanup", "Device Cleanup")]
    [InlineData("cleanmgr", "Очистка диска Windows")]
    public void DisplayName_maps_all_patterns(string pattern, string expected)
    {
        Assert.Equal(expected, CleanerToolCatalog.DisplayName(pattern));
    }

    [Fact]
    public void IsOblivionTool_detects_variants()
    {
        Assert.True(CleanerToolCatalog.IsOblivionTool("USBOblivion64.exe"));
        Assert.True(CleanerToolCatalog.IsOblivionTool("USB Oblivion"));
    }
}

public class UsbVendorDatabaseParserExtendedTests
{
    [Fact]
    public void Merge_merges_product_names_with_conflict_resolution()
    {
        var target = new UsbVendorDatabaseData();
        target.Vendors["0951"] = "Kingston";
        target.Products["0951"] = new Dictionary<string, string> { ["1666"] = "Unknown" };
        var source = new UsbVendorDatabaseData();
        source.Products["0951"] = new Dictionary<string, string> { ["1666"] = "DataTraveler 3.0" };

        UsbVendorDatabaseParser.Merge(target, source, sourceWinsOnConflict: true);

        Assert.Equal("DataTraveler 3.0", target.Products["0951"]["1666"]);
    }

    [Fact]
    public void ParseFile_reads_from_disk()
    {
        var path = Path.Combine(Path.GetTempPath(), $"usbids-{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, "0951  Kingston\n\t1666  DT\n");
        var data = UsbVendorDatabaseParser.ParseFile(path);
        Assert.Equal("Kingston", data.Vendors["0951"]);
    }
}
