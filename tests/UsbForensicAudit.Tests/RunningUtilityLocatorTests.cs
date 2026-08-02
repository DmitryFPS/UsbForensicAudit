using System.Diagnostics;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class RunningUtilityLocatorTests
{
    private static RunningExternalUtility Utility(
        string displayName = "USBDetector",
        string processName = "USBDetector",
        int processId = 1234,
        string utilityId = "usbdetector") => new()
    {
        UtilityId = utilityId,
        DisplayName = displayName,
        ProcessId = processId,
        ProcessName = processName,
        MainWindowTitle = "Окно",
        HasMainWindow = true
    };

    /// <summary>Живой процесс для проверки TryRefresh/Resolve: текущий тестовый процесс всегда жив.</summary>
    private static RunningExternalUtility LiveUtility(string displayName, string utilityId)
    {
        using var current = Process.GetCurrentProcess();
        return new RunningExternalUtility
        {
            UtilityId = utilityId,
            DisplayName = displayName,
            ProcessId = current.Id,
            ProcessName = current.ProcessName,
            MainWindowTitle = "",
            HasMainWindow = false
        };
    }

    [Theory]
    [InlineData("USBDetector", "USBDetector", "USBDetector.exe")]
    [InlineData("usbdeview", "USBDeview", "USBDeview.exe")]
    [InlineData("USBDeview.exe", "USBDeview", "USBDeview")]
    [InlineData("Отчёт USB Oblivion", "USB Oblivion", "USBOblivion64.exe")]
    public void NamesMatch_matches_report_name_to_process(string rowName, string displayName, string processName)
    {
        Assert.True(RunningUtilityLocator.NamesMatch(rowName, displayName, processName));
    }

    [Theory]
    [InlineData("Totally Different Tool", "USBDetector", "USBDetector.exe")]
    [InlineData("", "USBDetector", "USBDetector.exe")]
    [InlineData("   ", "USBDetector", "USBDetector.exe")]
    public void NamesMatch_rejects_unrelated_or_empty_names(string rowName, string displayName, string processName)
    {
        Assert.False(RunningUtilityLocator.NamesMatch(rowName, displayName, processName));
    }

    [Fact]
    public void ExtractProcmonSessionDirectory_returns_path_after_marker()
    {
        var message = "Procmon не смог завершить запись. Файлы: C:\\Data\\ProcmonSessions\\2024-01-01";
        Assert.Equal("C:\\Data\\ProcmonSessions\\2024-01-01", RunningUtilityLocator.ExtractProcmonSessionDirectory(message));
    }

    [Fact]
    public void ExtractProcmonSessionDirectory_uses_last_marker_occurrence()
    {
        var message = "Файлы: C:\\старое. Повтор. Файлы: C:\\новое";
        Assert.Equal("C:\\новое", RunningUtilityLocator.ExtractProcmonSessionDirectory(message));
    }

    [Fact]
    public void ExtractProcmonSessionDirectory_returns_null_without_marker()
    {
        Assert.Null(RunningUtilityLocator.ExtractProcmonSessionDirectory("Ошибка без пути к сессии."));
    }

    [Fact]
    public void TryRefresh_returns_null_for_dead_process()
    {
        var dead = Utility(processName: "definitely-not-a-real-process-name", processId: int.MaxValue - 1);
        Assert.Null(RunningUtilityLocator.TryRefresh(dead));
    }

    [Fact]
    public void TryRefresh_refreshes_live_process_and_keeps_identity()
    {
        var live = LiveUtility("USBDetector", "usbdetector");
        var refreshed = RunningUtilityLocator.TryRefresh(live);

        Assert.NotNull(refreshed);
        Assert.Equal(live.UtilityId, refreshed!.UtilityId);
        Assert.Equal(live.DisplayName, refreshed.DisplayName);
        Assert.Equal(live.ProcessId, refreshed.ProcessId);
    }

    [Fact]
    public void TryRefresh_finds_restarted_process_by_name_when_pid_is_stale()
    {
        using var current = Process.GetCurrentProcess();
        var stalePid = Utility(
            displayName: "USBDetector",
            processName: current.ProcessName,
            processId: int.MaxValue - 2);

        var refreshed = RunningUtilityLocator.TryRefresh(stalePid);

        Assert.NotNull(refreshed);
        Assert.Equal(current.ProcessName, refreshed!.ProcessName);
    }

    [Fact]
    public void Resolve_prefers_selected_utility_when_names_match()
    {
        var selected = LiveUtility("USBDetector", "usbdetector");
        var other = Utility(displayName: "USBDeview", processName: "definitely-not-real", processId: int.MaxValue - 3, utilityId: "usbdeview");

        var resolved = RunningUtilityLocator.Resolve("USBDetector", selected, [other], null);

        Assert.NotNull(resolved);
        Assert.Equal(selected.ProcessId, resolved!.ProcessId);
    }

    [Fact]
    public void Resolve_falls_back_to_known_list_when_selected_does_not_match()
    {
        var selected = Utility(displayName: "USBDeview", processName: "definitely-not-real", processId: int.MaxValue - 4, utilityId: "usbdeview");
        var known = LiveUtility("USBDetector", "usbdetector");

        var resolved = RunningUtilityLocator.Resolve("USBDetector", selected, [known], null);

        Assert.NotNull(resolved);
        Assert.Equal(known.ProcessId, resolved!.ProcessId);
    }

    [Fact]
    public void Resolve_falls_back_to_last_captured_utility()
    {
        var lastCaptured = LiveUtility("USBDetector", "usbdetector");

        var resolved = RunningUtilityLocator.Resolve("USBDetector", null, [], lastCaptured);

        Assert.NotNull(resolved);
        Assert.Equal(lastCaptured.ProcessId, resolved!.ProcessId);
    }

    [Fact]
    public void Resolve_matches_by_catalog_definition_when_names_differ()
    {
        // Имя строки узнаётся каталогом (USBDetector), но известный процесс
        // подписан другим display name — совпадение идёт по UtilityId.
        var known = LiveUtility("Переименованный детектор", "usbdetector");

        var resolved = RunningUtilityLocator.Resolve("USBDetector.exe", null, [known], null);

        Assert.NotNull(resolved);
        Assert.Equal("usbdetector", resolved!.UtilityId);
    }

    [Fact]
    public void Resolve_returns_null_for_unknown_utility()
    {
        Assert.Null(RunningUtilityLocator.Resolve("Неизвестная программа", null, [], null));
    }

    [Fact]
    public void Resolve_returns_null_when_all_candidates_are_dead()
    {
        var dead = Utility(processName: "definitely-not-real", processId: int.MaxValue - 5);

        Assert.Null(RunningUtilityLocator.Resolve("USBDetector", dead, [dead], dead));
    }
}
