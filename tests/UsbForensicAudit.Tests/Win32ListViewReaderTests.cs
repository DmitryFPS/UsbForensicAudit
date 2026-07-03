using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class Win32ListViewReaderTests
{
    [Fact]
    public void IsSnapshotUsable_requires_multiple_columns_for_ui_automation()
    {
        var singleColumn = new Win32ListViewReader.ListViewSnapshot(
            IntPtr.Zero,
            0,
            0,
            ["Name"],
            [new[] { "Only one" }]);

        var multiColumn = new Win32ListViewReader.ListViewSnapshot(
            IntPtr.Zero,
            0,
            0,
            ["A", "B"],
            [new[] { "x", "y" }]);

        Assert.False(Win32ListViewReader.IsSnapshotUsableForUiAutomation(singleColumn));
        Assert.True(Win32ListViewReader.IsSnapshotUsableForUiAutomation(multiColumn));
        Assert.True(Win32ListViewReader.IsSnapshotUsableForClipboard(singleColumn));
    }

    [Fact]
    public void IsOtherTracesTable_detects_vid_pid_table_without_uid()
    {
        var snapshot = new Win32ListViewReader.ListViewSnapshot(
            IntPtr.Zero,
            100,
            0,
            ["VID", "Производитель", "PID", "Модель", "Первое подключение"],
            [new[] { "0E0F", "VMware, Inc.", "0003", "Virtual Mouse", "10.10.2023 00:03" }]);

        Assert.True(Win32ListViewReader.IsOtherTracesTable(snapshot));
        Assert.False(Win32ListViewReader.IsMainRegistryTable(snapshot));
    }

    [Fact]
    public void IsMainRegistryTable_detects_uid_column()
    {
        var snapshot = new Win32ListViewReader.ListViewSnapshot(
            IntPtr.Zero,
            0,
            0,
            ["UID", "Производитель", "Модель", "Установка"],
            [new[] { "USB\\VID_1234&PID_5678\\x", "Test", "Device", "01.01.1970 06:00" }]);

        Assert.True(Win32ListViewReader.IsMainRegistryTable(snapshot));
        Assert.False(Win32ListViewReader.IsOtherTracesTable(snapshot));
    }

    [Fact]
    public void ScoreSnapshot_prefers_more_rows()
    {
        var small = new Win32ListViewReader.ListViewSnapshot(
            IntPtr.Zero,
            100,
            0,
            ["VID", "PID"],
            [new[] { "0E0F", "0003" }]);

        var large = new Win32ListViewReader.ListViewSnapshot(
            IntPtr.Zero,
            0,
            0,
            ["UID", "Производитель"],
            Enumerable.Range(0, 25).Select(i => new[] { $"USB\\VID_{i:X4}", "Vendor" }).ToArray());

        Assert.True(Win32ListViewReader.ScoreSnapshot(large) > Win32ListViewReader.ScoreSnapshot(small));
    }

    [Fact]
    public void IsSnapshotMisaligned_detects_shifted_usbdetector_row()
    {
        var snapshot = new Win32ListViewReader.ListViewSnapshot(
            IntPtr.Zero,
            0,
            0,
            ["VID", "Производитель", "PID", "Модель", "Первое подключение"],
            [new[] { "0E0F", "VMware, Inc.", "0003", "Virtual Mouse", "10.10.2023" }]);

        Assert.False(Win32ListViewReader.IsSnapshotMisaligned(snapshot));
    }

    [Fact]
    public void IsSnapshotUsable_rejects_empty_rows()
    {
        var empty = new Win32ListViewReader.ListViewSnapshot(IntPtr.Zero, 0, 0, ["A"], Array.Empty<IReadOnlyList<string>>());
        Assert.False(Win32ListViewReader.IsSnapshotUsableForUiAutomation(empty));
    }
}
