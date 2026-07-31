using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class PrivilegeStateTests
{
    [Fact]
    public void Administrator_without_backup_privilege_cannot_read_protected_registry()
    {
        var state = new PrivilegeState(IsAdministrator: true, IsLocalSystem: false,
            BackupPrivilegeEnabled: false, RestorePrivilegeEnabled: false);

        Assert.False(state.CanReadProtectedRegistry);
        Assert.Contains("SeBackupPrivilege", state.Describe(), StringComparison.Ordinal);
        Assert.Contains("не будет означать", state.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void Administrator_with_backup_privilege_can_read_protected_registry()
    {
        var state = new PrivilegeState(IsAdministrator: true, IsLocalSystem: false,
            BackupPrivilegeEnabled: true, RestorePrivilegeEnabled: true);

        Assert.True(state.CanReadProtectedRegistry);
        Assert.Contains("доступны", state.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void System_account_can_read_protected_registry()
    {
        var state = new PrivilegeState(IsAdministrator: false, IsLocalSystem: true,
            BackupPrivilegeEnabled: false, RestorePrivilegeEnabled: false);

        Assert.True(state.CanReadProtectedRegistry);
        Assert.Contains("SYSTEM", state.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void Unprivileged_scan_is_reported_as_incomplete()
    {
        var state = new PrivilegeState(IsAdministrator: false, IsLocalSystem: false,
            BackupPrivilegeEnabled: false, RestorePrivilegeEnabled: false);

        Assert.False(state.CanReadProtectedRegistry);
        Assert.Contains("неполон", state.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void Failure_reason_is_carried_into_the_report_text()
    {
        var state = new PrivilegeState(IsAdministrator: true, IsLocalSystem: false,
            BackupPrivilegeEnabled: false, RestorePrivilegeEnabled: false)
        {
            BackupPrivilegeError = "Привилегия SeBackupPrivilege не назначена процессу."
        };

        Assert.Contains("не назначена процессу", state.Describe(), StringComparison.Ordinal);
    }
}
