using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class RegistryTraceAccessTests
{
    [Fact]
    public void Native_preview_reads_hklm_without_requesting_write_access_or_creating_a_missing_key()
    {
        var path = @"HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices\USB#VID_1234&PID_5678#TEST-" + Guid.NewGuid().ToString("N");
        var platform = new WindowsDeviceRemovalPlatform(Path.GetTempPath());
        Assert.Null(platform.ReadTraceFingerprint(path));
        Assert.Null(platform.ReadTraceFingerprint(path));
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        Assert.Null(machine.OpenSubKey(path[5..]));
    }

    [Fact]
    public void Native_inventory_retains_exact_ids_and_parent_information_without_mutation()
    {
        var platform = new WindowsDeviceRemovalPlatform(Path.GetTempPath());
        var inventory = platform.ReadInventory();
        Assert.Equal(inventory.Count, inventory.Select(x => x.InstanceId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var node in inventory)
        {
            Assert.Equal(3, node.InstanceId.Split('\\').Length);
            Assert.DoesNotContain("HTREE", node.ParentDeviceInstanceId, StringComparison.OrdinalIgnoreCase);
            if (node.Present is null)
            {
                Assert.NotEmpty(DeviceRemovalPolicy.ProtectionReason(node, [node]));
            }
        }
    }

    [Theory]
    [InlineData(@"HKLM\SYSTEM")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Enum\USB")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_1234&PID_5678\S\Properties")]
    [InlineData(@"HKCU\Software\Test")]
    public void Backup_rejects_broad_or_unrelated_path(string path)
        => Assert.Throws<ArgumentException>(() => RegistryTraceAccess.ValidatePath(path, true));

    [Fact]
    public void Backup_allows_exact_active_instance_but_direct_delete_does_not()
    {
        const string path = @"HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_1234&PID_5678\S";
        Assert.StartsWith("HKEY_LOCAL_MACHINE", RegistryTraceAccess.ValidatePath(path, true));
        Assert.Throws<ArgumentException>(() => RegistryTraceAccess.ValidatePath(path, false));
    }

    [Fact]
    public void Missing_preview_path_stays_absent_and_does_not_create_parents()
    {
        using var fixture = new RegistryFixture();
        Assert.Null(RegistryTraceAccess.ReadFingerprint(fixture.Root, @"missing\child", "selected"));
        Assert.Empty(fixture.Root.GetSubKeyNames());
    }

    [Fact]
    public void Fingerprint_covers_nested_values_names_types_and_raw_contents()
    {
        using var fixture = new RegistryFixture();
        using var selected = fixture.Root.CreateSubKey(@"selected\Properties\nested");
        selected.SetValue("", "default");
        selected.SetValue("binary", new byte[] { 0, 1, 255 }, RegistryValueKind.Binary);
        selected.SetValue("expand", "%TEMP%", RegistryValueKind.ExpandString);
        selected.SetValue("multi", new[] { "first", "second" }, RegistryValueKind.MultiString);
        selected.SetValue("qword", 0x123456789L, RegistryValueKind.QWord);
        var original = Read(fixture.Root);
        Assert.NotNull(original);
        Assert.Equal(original, Read(fixture.Root));
        selected.SetValue("binary", new byte[] { 0, 2, 255 }, RegistryValueKind.Binary);
        Assert.NotEqual(original, Read(fixture.Root));
        selected.SetValue("binary", new byte[] { 0, 1, 255 }, RegistryValueKind.Binary);
        Assert.Equal(original, Read(fixture.Root));
        selected.SetValue("expand", "%TEMP%", RegistryValueKind.String);
        Assert.NotEqual(original, Read(fixture.Root));
    }

    [Fact]
    public void Changed_fingerprint_keeps_selected_tree_and_sibling()
    {
        using var fixture = new RegistryFixture();
        using var selected = fixture.Root.CreateSubKey(@"selected\Properties");
        using var sibling = fixture.Root.CreateSubKey("sibling");
        selected.SetValue("value", "before");
        var original = Read(fixture.Root)!;
        selected.SetValue("value", "after");
        Assert.Throws<IOException>(() => RegistryTraceAccess.DeleteTree(fixture.Root, "selected", "selected", original));
        Assert.Equal(new[] { "selected", "sibling" }, fixture.Root.GetSubKeyNames().Order().ToArray());
        Assert.Equal("after", selected.GetValue("value"));
    }

    [Fact]
    public void Delete_removes_exact_tree_including_properties_and_preserves_sibling()
    {
        using var fixture = new RegistryFixture();
        using (var selected = fixture.Root.CreateSubKey(@"selected\Properties\nested"))
        {
            selected.SetValue("value", "data");
        }

        using (var sibling = fixture.Root.CreateSubKey("sibling"))
        {
            sibling.SetValue("keep", 7);
        }

        RegistryTraceAccess.DeleteTree(fixture.Root, "selected", "selected", Read(fixture.Root)!);
        Assert.Null(fixture.Root.OpenSubKey("selected"));
        using var remaining = fixture.Root.OpenSubKey("sibling");
        Assert.Equal(7, remaining!.GetValue("keep"));
        RegistryTraceAccess.DeleteTree(fixture.Root, "selected", "selected", "old");
        Assert.Single(fixture.Root.GetSubKeyNames());
    }

    [Fact]
    public void Oversized_tree_is_rejected_before_any_delete()
    {
        using var fixture = new RegistryFixture();
        using (var selected = fixture.Root.CreateSubKey("selected\\" + string.Join('\\', Enumerable.Repeat("nested", 17))))
        {
            selected.SetValue("keep", "yes");
        }

        Assert.Throws<IOException>(() => RegistryTraceAccess.DeleteTree(fixture.Root, "selected", "selected", "unused"));
        using var remaining = fixture.Root.OpenSubKey("selected");
        Assert.NotNull(remaining);
    }

    [Theory]
    [InlineData(@"selected\..\sibling")]
    [InlineData(@"selected\\child")]
    [InlineData("")]
    public void Native_root_traversal_rejects_ambiguous_paths(string path)
    {
        using var fixture = new RegistryFixture();
        Assert.Throws<ArgumentException>(() => RegistryTraceAccess.ReadFingerprint(fixture.Root, path, "x"));
    }

    [Fact]
    public void Preview_does_not_change_callers_identity()
    {
        using var fixture = new RegistryFixture();
        var before = WindowsIdentity.GetCurrent().User!.Value;
        Assert.Null(Read(fixture.Root));
        Assert.Equal(before, WindowsIdentity.GetCurrent().User!.Value);
        Assert.Throws<ArgumentException>(() => RegistryTraceAccess.ReadFingerprint(fixture.Root, "..", "x"));
        Assert.Equal(before, WindowsIdentity.GetCurrent().User!.Value);
    }

    private static string? Read(RegistryKey root) => RegistryTraceAccess.ReadFingerprint(root, "selected", "selected");

    private sealed class RegistryFixture : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "UsbForensicAudit-hive-" + Guid.NewGuid().ToString("N"));
        internal RegistryKey Root { get; }
        internal RegistryFixture()
        {
            Directory.CreateDirectory(_directory);
            // Отдельный файл, не подключаемый к реестру ОС; администратор не нужен.
            var error = RegLoadAppKey(Path.Combine(_directory, "fixture.hiv"), out var handle, 0xF003F, 1, 0);
            if (error != 0)
            {
                handle?.Dispose();
                throw new System.ComponentModel.Win32Exception(error);
            }
            Root = RegistryKey.FromHandle(handle, RegistryView.Registry64);
        }
        public void Dispose()
        {
            Root.Dispose();
            Directory.Delete(_directory, recursive: true);
        }
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int RegLoadAppKey(string path, out SafeRegistryHandle handle, int access, int options, int reserved);
    }
}
