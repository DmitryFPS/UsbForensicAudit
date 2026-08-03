using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Тесты логики вкладки сторонних утилит, выделенной из code-behind MainWindow:
/// оценка строк с procmon-доказательствами, снапшот и его персистентность.
/// До рефакторинга эта логика жила в окне и не тестировалась вовсе.
/// </summary>
public sealed class ExternalUtilitiesViewModelTests : IDisposable
{
    private readonly string _tempDirectory =
        Path.Combine(Path.GetTempPath(), "ufa-extvm-" + Guid.NewGuid().ToString("N"));

    public ExternalUtilitiesViewModelTests()
    {
        Directory.CreateDirectory(_tempDirectory);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDirectory))
            {
                Directory.Delete(_tempDirectory, true);
            }
        }
        catch (IOException)
        {
            // Уборка временной папки — по возможности.
        }
    }

    private ExternalUtilitiesViewModel CreateVm(AuditResult? audit = null) =>
        new(_tempDirectory, () => audit);

    private static ExternalUtilityRow CreateRow() =>
        ExternalUtilityManualParser.Parse("Kingston DataTraveler 3.0\tVID_0951&PID_1666\tSerial 001A92053B6A");

    private static ExternalUtilitySourceHit CreateProcmonHit() => new()
    {
        Title = "Procmon",
        RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",
        Found = true,
        ResultText = "прямой источник (реестр)",
        IsProcmonEvidence = true,
        Operation = "RegQueryValue",
        ObservedAtUtc = DateTimeOffset.UtcNow
    };

    [Fact]
    public void Assess_without_procmon_returns_assessment_without_procmon_evidence()
    {
        var vm = CreateVm(new AuditResult());
        var row = CreateRow();

        var assessment = vm.Assess(row);

        Assert.False(assessment.HasProcmonEvidence);
        Assert.False(string.IsNullOrWhiteSpace(assessment.VerdictTitle));
        Assert.False(string.IsNullOrWhiteSpace(assessment.FullExplanation));
    }

    [Fact]
    public void Assess_uses_recorded_procmon_evidence()
    {
        var vm = CreateVm(new AuditResult());
        var row = CreateRow();
        vm.RecordProcmonResult(row, [CreateProcmonHit()], _tempDirectory, "сводка procmon");

        var assessment = vm.Assess(row);

        Assert.True(assessment.HasProcmonEvidence);
        Assert.Equal(_tempDirectory, assessment.ProcmonSessionDirectory);
    }

    [Fact]
    public void TryGetProcmonSessionDirectory_reflects_recorded_state()
    {
        var vm = CreateVm();
        var row = CreateRow();

        Assert.False(vm.TryGetProcmonSessionDirectory(row, out _));

        vm.RecordProcmonSessionDirectory(row, _tempDirectory);

        Assert.True(vm.TryGetProcmonSessionDirectory(row, out var directory));
        Assert.Equal(_tempDirectory, directory);
    }

    [Fact]
    public void RefreshAssessments_fills_display_fields_of_rows()
    {
        var vm = CreateVm(new AuditResult());
        var row = CreateRow();
        vm.Rows.Add(row);

        vm.RefreshAssessments();

        Assert.False(string.IsNullOrWhiteSpace(row.AnalysisText));
        Assert.NotEqual("—", row.VerdictDisplayText);
    }

    [Fact]
    public async Task Snapshot_round_trips_rows_and_utility_name_through_disk()
    {
        var vm = CreateVm();
        vm.Rows.Add(CreateRow());

        await vm.SaveSnapshotAsync("USBDetector");

        var restored = CreateVm();
        restored.LoadSnapshotFromDisk();
        restored.RestoreFromSnapshot();

        Assert.Single(restored.Rows);
        Assert.NotNull(restored.SnapshotForReport);
        Assert.Equal("USBDetector", restored.SnapshotForReport!.UtilityName);
    }

    [Fact]
    public void SnapshotForReport_is_null_when_nothing_captured()
    {
        var vm = CreateVm();
        vm.LoadSnapshotFromDisk();

        Assert.Null(vm.SnapshotForReport);
    }

    [Fact]
    public void RefreshHistoricalLaunches_with_null_audit_clears_list()
    {
        var vm = CreateVm();
        vm.HistoricalLaunches.Add(new HistoricalUtilityLaunch
        {
            ToolName = "USBDeview",
            Source = "Prefetch",
            TimestampUtc = DateTimeOffset.UtcNow,
            Summary = "тест"
        });

        vm.RefreshHistoricalLaunches(null);

        Assert.Empty(vm.HistoricalLaunches);
    }

    [Fact]
    public void BuildBriefAnalysis_mentions_procmon_when_evidence_recorded()
    {
        var vm = CreateVm(new AuditResult());
        var row = CreateRow();
        vm.RecordProcmonResult(row, [CreateProcmonHit()], _tempDirectory, "сводка");

        var text = ExternalUtilitiesViewModel.BuildBriefAnalysis(vm.Assess(row), row);

        Assert.Contains("Procmon", text, StringComparison.Ordinal);
        Assert.Contains("Откуда строка", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Observable_state_properties_round_trip()
    {
        var vm = CreateVm();
        var row = CreateRow();

        vm.ActiveRow = row;
        vm.AnalysisCopyText = "разбор";

        Assert.Same(row, vm.ActiveRow);
        Assert.Equal("разбор", vm.AnalysisCopyText);
        Assert.Null(vm.LastCapturedUtility);
    }
}
