using System.IO;
using ClosedXML.Excel;
using Microsoft.Data.Sqlite;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class Stage7IntegrationTests
{
    [Fact]
    public async Task Orchestrator_runs_pipeline_in_order_and_persists_coverage()
    {
        var order = new List<string>();
        var storage = new RecordingAuditStorage(order);
        var orchestrator = new AuditOrchestrator(
            new FakeDeviceCollector(order),
            new IEvidenceCollector[]
            {
                new FakeEvidenceCollector(order, "SetupApi", 2),
                new FakeEvidenceCollector(order, "EventLog", 1, shouldRun: false),
                new FakeEvidenceCollector(order, "UserArtifacts", 3)
            },
            new FakeHistoricalCollector(order),
            new CorrelationService(),
            new NoOpLiveMerger(order),
            new TimelineEnricher(),
            new CleanupDetector(),
            storage,
            new FakePrivilegeChecker());

        var result = await orchestrator.RunFullScanAsync();

        Assert.Equal(
            new[]
            {
                "FakeDeviceCollector.Collect",
                "FakeEvidence.SetupApi.Collect",
                "FakeEvidence.UserArtifacts.Collect",
                "FakeHistorical.Collect",
                "NoOpLiveMerger.Merge",
                "RecordingAuditStorage.Save"
            },
            order);

        Assert.True(result.IsAdministrator);
        Assert.NotNull(storage.Saved);
        Assert.Equal(result.SessionId, storage.Saved.SessionId);
        Assert.Equal(3, result.Devices.Count);
        Assert.True(result.Evidence.Count >= 6);
        Assert.Contains(result.Evidence, x => x.Source == "Correlation");
        Assert.Contains(result.Evidence, x => x.Source == "Historical residual");

        Assert.Equal(5, result.Coverage.Sources.Count);
        Assert.Contains(result.Coverage.Sources, x => x.Source == "FakeEvidenceCollector" && x.Status == "NotRun");
        Assert.Equal("Complete", result.Coverage.Sources.Single(x => x.Source == "FakeDeviceCollector").Status);
        Assert.True(result.Coverage.CanonicalDeviceCount >= 1);
        Assert.Contains(result.Devices, x => x.FirstConnectedUtc.HasValue);
        Assert.True(result.FinishedAtUtc >= result.StartedAtUtc);
        Assert.NotEmpty(result.Devices[0].CanonicalDeviceId);
        var storageRecord = result.Devices.Single(x => x.DeviceInstanceId.StartsWith("USBSTOR", StringComparison.Ordinal));
        Assert.Equal("MSC/USBSTOR", storageRecord.Transport);
    }

    [Fact]
    public async Task Orchestrator_isolates_failed_collectors_and_records_error_coverage()
    {
        var order = new List<string>();
        var storage = new RecordingAuditStorage(order);
        var orchestrator = new AuditOrchestrator(
            new FakeDeviceCollector(order),
            new IEvidenceCollector[]
            {
                new ThrowingEvidenceCollector(),
                new FakeEvidenceCollector(order, "Healthy", 1)
            },
            new FakeHistoricalCollector(order),
            new CorrelationService(),
            new NoOpLiveMerger(order),
            new TimelineEnricher(),
            new CleanupDetector(),
            storage,
            new FakePrivilegeChecker());

        var result = await orchestrator.RunFullScanAsync();

        Assert.NotNull(storage.Saved);
        Assert.Contains(result.Evidence, evidence => evidence.Source == "Healthy");
        Assert.Contains(result.SourceWarnings, warning =>
            warning.Contains("simulated collector failure", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Coverage.Sources, source =>
            source.Source == nameof(ThrowingEvidenceCollector) && source.Status == "Error");
    }

    [Fact]
    public void Golden_fixture_builds_usb_scope_report_context_for_transport_variants()
    {
        var result = GoldenAuditFixtures.CreateTransportScopeResult();

        DeviceTransportClassifier.ClassifyAll(result.Devices);
        DeviceIdentityGraph.Process(result.Devices);
        VolumeCorrelationService.Process(result);
        result.Evidence.AddRange(new CorrelationService().BuildDeviceCorrelations(result));
        new TimelineEnricher().Enrich(result);
        AuditOrchestrator.CalculateDateCoverage(result);

        var context = ForensicReportContext.Create(result);

        Assert.True(context.ReportableDevices.Count >= 4);
        Assert.Contains(context.ReportableDevices, x => x.Transport == "UASP/SCSI");
        Assert.Contains(context.ReportableDevices, x => x.Transport == "MTP/PTP/WPD");
        Assert.Contains(context.ReportableDevices, x => x.Connection == "PCIe-tunneled candidate");
        Assert.DoesNotContain(context.ReportableDevices, x => x.DeviceInstanceId.Contains("NVME-INTERNAL", StringComparison.Ordinal));

        var uasp = context.ReportableDevices.Single(x => x.Transport == "UASP/SCSI");
        var usbBridge = context.ReportableDevices.Single(x => x.DeviceInstanceId.Contains("152D", StringComparison.Ordinal));
        Assert.Equal(usbBridge.CanonicalDeviceId, uasp.CanonicalDeviceId);

        var distinctSerials = result.Devices
            .Where(x => x.Serial is "SERIAL-A" or "SERIAL-B")
            .Select(x => x.CanonicalDeviceId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        Assert.Equal(2, distinctSerials.Length);

        Assert.Contains(context.Timeline, x => x.Source == "EventLog: System");
        Assert.DoesNotContain(context.Timeline, x => x.DeviceHint == "Win32_PhysicalMemory");
        Assert.True(result.Coverage.ExactDateCoveragePercent > 0);
    }

    [Fact]
    public void Golden_fixture_html_and_excel_surface_coverage_and_identity_fields()
    {
        var result = GoldenAuditFixtures.CreateTransportScopeResult();
        DeviceTransportClassifier.ClassifyAll(result.Devices);
        DeviceIdentityGraph.Process(result.Devices);
        AuditOrchestrator.CalculateDateCoverage(result);
        result.Coverage.Sources.Add(new SourceCoverage
        {
            Source = "FakeCollector",
            Status = "Partial",
            Count = 10,
            Capped = true,
            Limit = 4000,
            Error = "collector: достигнут лимит 4000 записей"
        });

        var html = ForensicReportBuilder.BuildHtml(result);
        Assert.Contains("Область отчёта", html);
        Assert.Contains("Покрытие источников", html);
        Assert.Contains("canonical devices с точной датой", html);
        Assert.Contains("UASP/SCSI", html);
        Assert.Contains("MTP/PTP/WPD", html);
        Assert.Contains("Direct / High", html);
        Assert.DoesNotContain("NVME-INTERNAL", html);

        var directory = Path.Combine(Path.GetTempPath(), $"ufa-stage7-{Guid.NewGuid():N}");
        try
        {
            var excelPath = new ReportService().CreateExcel(result, directory);
            Assert.True(File.Exists(excelPath));
            Assert.True(new FileInfo(excelPath).Length > 1000);
            using (var workbook = new XLWorkbook(excelPath))
            {
                var evidence = workbook.Worksheet("Доказательства");
                Assert.Equal("Сила доказательства", evidence.Cell("D4").GetString());
                Assert.Contains(evidence.Column(4).CellsUsed(), x => x.GetString() == "Direct");
            }

            var pdfPath = new ReportService().CreatePdf(result, directory);
            Assert.True(File.Exists(pdfPath));
            Assert.Equal("%PDF", System.Text.Encoding.ASCII.GetString(File.ReadAllBytes(pdfPath), 0, 4));
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
    public async Task Orchestrator_deduplicates_user_artifacts_before_historical_phase()
    {
        var order = new List<string>();
        var storage = new RecordingAuditStorage(order);
        var duplicate = new EvidenceRecord
        {
            Source = "MountPoints2",
            UserSid = "S-1-5-21-1",
            DeviceHint = @"E:\case",
            SourceRecord = @"MountPoints2\E"
        };
        var orchestrator = new AuditOrchestrator(
            new FakeDeviceCollector(order, devices: 0),
            new IEvidenceCollector[] { new FakeEvidenceCollector(order, "UserArtifacts", 0, [duplicate, duplicate]) },
            new FakeHistoricalCollector(order),
            new CorrelationService(),
            new NoOpLiveMerger(order),
            new TimelineEnricher(),
            new CleanupDetector(),
            storage,
            new FakePrivilegeChecker());

        var result = await orchestrator.RunFullScanAsync();

        Assert.Single(result.Evidence, x => x.Source == "MountPoints2");
        Assert.Contains("FakeHistorical.Collect", order);
        Assert.True(order.IndexOf("FakeEvidence.UserArtifacts.Collect") < order.IndexOf("FakeHistorical.Collect"));
    }

    [Fact]
    public void Storage_round_trip_preserves_golden_session_with_coverage()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ufa-stage7-storage-{Guid.NewGuid():N}");
        try
        {
            var storage = new AuditStorage(directory);
            var result = GoldenAuditFixtures.CreateTransportScopeResult();
            result.SessionId = "stage7-golden";
            DeviceTransportClassifier.ClassifyAll(result.Devices);
            DeviceIdentityGraph.Process(result.Devices);
            result.Coverage.Sources.Add(new SourceCoverage { Source = "Golden", Status = "Complete", Count = 4 });
            AuditOrchestrator.CalculateDateCoverage(result);

            storage.Save(result);
            var loaded = storage.Load("stage7-golden");

            Assert.NotNull(loaded);
            Assert.Equal(result.Devices.Count, loaded.Devices.Count);
            Assert.True(loaded.Coverage.ExactDateCoveragePercent > 0);
            Assert.Contains(loaded.Coverage.Sources, x => x.Source == "Golden");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, true);
            }
        }
    }

    private sealed class FakeDeviceCollector(List<string> order, int devices = 3) : IUsbDeviceCollector
    {
        public string ProgressMessage => "fake devices";

        public IReadOnlyList<UsbDeviceRecord> Collect(List<string> warnings)
        {
            order.Add("FakeDeviceCollector.Collect");
            if (devices == 0)
            {
                return [];
            }

            return
            [
                new UsbDeviceRecord
                {
                    VisualCategory = "RealUsb",
                    DeviceType = "USB",
                    Source = "Registry: USB",
                    DeviceInstanceId = @"USB\VID_0951&PID_1666\SERIAL-A",
                    Vid = "0951",
                    Pid = "1666",
                    Serial = "SERIAL-A",
                    FirstConnectedUtc = DateTimeOffset.Parse("2026-01-01T10:00:00Z"),
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
                    Serial = "SERIAL-B"
                },
                new UsbDeviceRecord
                {
                    VisualCategory = "RelatedStorage",
                    DeviceType = "USBSTOR",
                    Source = "Registry: USBSTOR",
                    DeviceInstanceId = @"USBSTOR\Disk&Ven_Kingston&Prod_Flash\SERIAL-A&0",
                    Serial = "SERIAL-A"
                }
            ];
        }
    }

    private sealed class FakeEvidenceCollector(
        List<string> order,
        string name,
        int count,
        IReadOnlyList<EvidenceRecord>? preset = null,
        bool shouldRun = true) : IEvidenceCollector
    {
        public string ProgressMessage => $"fake {name}";

        public bool ShouldRun => shouldRun;

        public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings)
        {
            if (!shouldRun)
            {
                order.Add($"FakeEvidence.{name}.Skip");
                return [];
            }

            order.Add($"FakeEvidence.{name}.Collect");
            if (preset is not null)
            {
                return preset.ToArray();
            }

            return Enumerable.Range(0, count)
                .Select(i => new EvidenceRecord
                {
                    TimestampUtc = DateTimeOffset.Parse("2026-01-02T12:00:00Z").AddMinutes(i),
                    Source = name,
                    DeviceHint = @"USB\VID_0951&PID_1666\SERIAL-A",
                    Summary = $"evidence {i}",
                    RawText = "VID_0951&PID_1666 SERIAL-A"
                })
                .ToArray();
        }
    }

    private sealed class FakeHistoricalCollector(List<string> order) : IHistoricalArtifactCollector
    {
        public string ProgressMessage => "fake historical";

        public void Collect(AuditResult result, CancellationToken cancellationToken = default)
        {
            order.Add("FakeHistorical.Collect");
            result.Evidence.Add(new EvidenceRecord
            {
                Source = "Historical residual",
                Summary = "DeviceMigration residual",
                Provenance = "fake historical collector"
            });
        }
    }

    private sealed class ThrowingEvidenceCollector : IEvidenceCollector
    {
        public string ProgressMessage => "throwing";
        public bool ShouldRun => true;

        public IReadOnlyList<EvidenceRecord> Collect(List<string> warnings) =>
            throw new InvalidOperationException("simulated collector failure");
    }

    private sealed class NoOpLiveMerger(List<string> order) : ILiveDeviceMerger
    {
        public void Merge(AuditResult result) => order.Add("NoOpLiveMerger.Merge");
    }

    private sealed class RecordingAuditStorage(List<string> order) : IAuditStorage
    {
        public string DataDirectory { get; } = Path.GetTempPath();
        public string DatabasePath => Path.Combine(DataDirectory, "fake.sqlite");
        public AuditResult? Saved { get; private set; }

        public void Save(AuditResult result)
        {
            order.Add("RecordingAuditStorage.Save");
            Saved = result;
        }

        public AuditResult? Load(string sessionId) => Saved?.SessionId == sessionId ? Saved : null;
    }

    private sealed class FakePrivilegeChecker : IPrivilegeChecker
    {
        public bool IsAdministrator() => true;
    }

    private static class GoldenAuditFixtures
    {
        public static AuditResult CreateTransportScopeResult()
        {
            var started = DateTimeOffset.Parse("2026-03-01T08:00:00Z");
            var result = new AuditResult
            {
                StartedAtUtc = started,
                FinishedAtUtc = started.AddMinutes(2)
            };

            var container = "{8B202FD7-8D72-4124-A711-C3849D29F245}";
            result.Devices.AddRange(
            [
                new UsbDeviceRecord
                {
                    VisualCategory = "RealUsb",
                    DeviceType = "USB",
                    Source = "Registry: USB",
                    DeviceInstanceId = @"USB\VID_152D&PID_0562\BRIDGE01",
                    Vid = "152D",
                    Pid = "0562",
                    Serial = "BRIDGE01",
                    ContainerId = container,
                    FirstConnectedUtc = started,
                    ConnectionDisplayKind = "ExactEvent"
                },
                new UsbDeviceRecord
                {
                    VisualCategory = "RelatedStorage",
                    DeviceType = "SCSI Storage",
                    Source = "Registry: SCSI",
                    DeviceInstanceId = @"SCSI\Disk&Ven_JMicron&Prod_Generic\7&456&0&000000",
                    Serial = "7&456&0&000000",
                    Service = "uaspstor",
                    ContainerId = container
                },
                new UsbDeviceRecord
                {
                    VisualCategory = "RealUsb",
                    DeviceType = "WPD",
                    Source = "Registry: SWD\\WPDBUSENUM",
                    DeviceInstanceId = @"SWD\WPDBUSENUM\{A1B2C3}#0000000000000000",
                    FriendlyName = "MTP USB Device"
                },
                new UsbDeviceRecord
                {
                    VisualCategory = "RealUsb",
                    DeviceType = "PCIe",
                    Source = "Registry: USB4",
                    DeviceInstanceId = @"PCI\VEN_8086&DEV_15EF\NVME-ENCLOSURE",
                    Product = "NVMe enclosure",
                    Service = "stornvme",
                    CompatibleIds = "THUNDERBOLT\\External_NVM_Express",
                    LocationPaths = "PCIROOT(0)#PCI(0700)#USB4(1)"
                },
                new UsbDeviceRecord
                {
                    VisualCategory = "RelatedStorage",
                    DeviceType = "SCSI",
                    Source = "Registry: SCSI",
                    DeviceInstanceId = @"SCSI\Disk&Ven_NVMe&Prod_Internal\4&111&0&000000",
                    Serial = "NVME-INTERNAL",
                    Product = "Internal NVMe SSD",
                    Service = "stornvme",
                    LocationPaths = "PCIROOT(0)#PCI(0100)"
                },
                new UsbDeviceRecord
                {
                    VisualCategory = "RealUsb",
                    DeviceType = "USB",
                    Source = "Registry: USB",
                    DeviceInstanceId = @"USB\VID_1234&PID_5678\SERIAL-A",
                    Vid = "1234",
                    Pid = "5678",
                    Serial = "SERIAL-A",
                    FirstConnectedUtc = started.AddHours(1),
                    ConnectionDisplayKind = "PnpDevProperty"
                },
                new UsbDeviceRecord
                {
                    VisualCategory = "RealUsb",
                    DeviceType = "USB",
                    Source = "Registry: USB",
                    DeviceInstanceId = @"USB\VID_1234&PID_5678\SERIAL-B",
                    Vid = "1234",
                    Pid = "5678",
                    Serial = "SERIAL-B"
                }
            ]);

            result.Evidence.Add(new EvidenceRecord
            {
                TimestampUtc = started,
                Source = "EventLog: System",
                EvidenceStrength = "Direct",
                Confidence = "High",
                Provenance = "Windows Event Log test fixture",
                DeviceHint = @"USB\VID_152D&PID_0562\BRIDGE01",
                Summary = "USB device started"
            });
            result.Evidence.Add(new EvidenceRecord
            {
                TimestampUtc = started,
                Source = "WMI",
                DeviceHint = "Win32_PhysicalMemory",
                Summary = "RAM module"
            });

            return result;
        }
    }
}
