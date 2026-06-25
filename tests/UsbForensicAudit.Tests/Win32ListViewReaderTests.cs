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
}
