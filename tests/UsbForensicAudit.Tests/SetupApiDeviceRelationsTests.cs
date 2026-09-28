using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class SetupApiDeviceRelationsTests
{
    private const string Child = @"USB\VID_04E8&PID_6860&MI_00\6&1113778F&0&0000";
    private const string Parent = @"USB\VID_04E8&PID_6860\1CB942B917047ECE";

    [Fact]
    public void RestoresCompositeParentFromExactSetupApiSection()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Child.ToLowerInvariant() };
        SetupApiDeviceRelations.Apply([device], [Evidence(Section(Child, Parent))]);
        Assert.Equal(Parent, device.ParentDeviceInstanceId);
        Assert.Empty(device.IdentityAliases);
    }

    [Theory]
    [InlineData(@"USB\ROOT_HUB30\4&91BAC8E&0&0")]
    [InlineData(@"USB\VID_05E3&PID_6860\OTHER")]
    [InlineData(@"USB\VID_04E8&PID_6861\OTHER")]
    [InlineData(@"USB\VID_04E8&PID_6860&MI_01\OTHER")]
    [InlineData(@"USB\VID_04E8&PID_6860\OTHER\NESTED")]
    [InlineData(@"USB\VID_04E8&PID_6860\*")]
    public void RejectsHubOtherModelInterfaceAndMalformedParents(string parent)
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Child };
        SetupApiDeviceRelations.Apply([device], [Evidence(Section(Child, parent))]);
        Assert.Empty(device.ParentDeviceInstanceId);
    }

    [Fact]
    public void RepeatedSameParentIsAcceptedButConflictingHistoricalParentsAreNot()
    {
        var same = new UsbDeviceRecord { DeviceInstanceId = Child };
        SetupApiDeviceRelations.Apply([same], [Evidence(Section(Child, Parent)), Evidence(Section(Child, Parent.ToLowerInvariant()))]);
        Assert.Equal(Parent, same.ParentDeviceInstanceId);
        var conflict = new UsbDeviceRecord { DeviceInstanceId = Child };
        SetupApiDeviceRelations.Apply([conflict], [Evidence(Section(Child, Parent)), Evidence(Section(Child, Parent + "-OTHER"))]);
        Assert.Empty(conflict.ParentDeviceInstanceId);
    }

    [Fact]
    public void UnsupportedSecondParentAlsoMakesHistoryAmbiguous()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Child };
        SetupApiDeviceRelations.Apply([device], [Evidence(Section(Child, Parent)), Evidence(Section(Child, @"USB\ROOT_HUB30\HUB"))]);
        Assert.Empty(device.ParentDeviceInstanceId);
    }

    [Fact]
    public void RequiresExactChildHeaderAndInstallBlockNotSubstringOrHint()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Child };
        var wrongHeader = Section(Child + "-OTHER", Parent);
        var wrongBlock = Section(Child, Parent).Replace("{Install Device - " + Child, "{Install Device - " + Child + "-OTHER", StringComparison.Ordinal);
        var hintOnly = Evidence("dvi: Parent Device: " + Parent);
        hintOnly.DeviceHint = Child;
        SetupApiDeviceRelations.Apply([device], [Evidence(wrongHeader), Evidence(wrongBlock), hintOnly]);
        Assert.Empty(device.ParentDeviceInstanceId);
    }

    [Fact]
    public void SectionBoundaryAndSectionEndCannotLeakParents()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Child };
        var ended = Section(Child, Parent).Replace("     dvi: Parent Device:", "<<<  Section end\n     dvi: Parent Device:", StringComparison.Ordinal);
        var unrelated = Section(Child, Parent).Replace("     dvi: Parent Device:", ">>>  [Other task]\n     dvi: Parent Device:", StringComparison.Ordinal);
        SetupApiDeviceRelations.Apply([device], [Evidence(ended), Evidence(unrelated)]);
        Assert.Empty(device.ParentDeviceInstanceId);
    }

    [Fact]
    public void OtherProviderCannotSupplyParentAndExistingValueIsNotOverwritten()
    {
        var record = Evidence(Section(Child, Parent));
        record.Provider = "EventLog";
        var device = new UsbDeviceRecord { DeviceInstanceId = Child };
        SetupApiDeviceRelations.Apply([device], [record]);
        Assert.Empty(device.ParentDeviceInstanceId);
        device.ParentDeviceInstanceId = Parent + "-LIVE";
        SetupApiDeviceRelations.Apply([device], [Evidence(Section(Child, Parent))]);
        Assert.Equal(Parent + "-LIVE", device.ParentDeviceInstanceId);
    }

    [Fact]
    public void ConfigureBlockAndMultipleSectionsAreSupported()
    {
        var device = new UsbDeviceRecord { DeviceInstanceId = Child };
        var sibling = Child.Replace("MI_00", "MI_01", StringComparison.Ordinal).Replace("0000", "0001", StringComparison.Ordinal);
        var siblingDevice = new UsbDeviceRecord { DeviceInstanceId = sibling };
        var text = Section(Child, Parent).Replace("{Install Device", "{Configure Device", StringComparison.Ordinal)
                   + Environment.NewLine + Section(sibling, Parent);
        SetupApiDeviceRelations.Apply([device, siblingDevice], [Evidence(text)]);
        Assert.Equal(Parent, device.ParentDeviceInstanceId);
        Assert.Equal(Parent, siblingDevice.ParentDeviceInstanceId);
    }

    private static EvidenceRecord Evidence(string text) => new() { Provider = "SetupAPI", RawText = text };

    [Fact]
    public void ReadsSingleLineStoredEvidenceAndDoesNotLeakAcrossClosedBlocks()
    {
        var child = new UsbDeviceRecord { DeviceInstanceId = Child };
        var flat = System.Text.RegularExpressions.Regex.Replace(Section(Child, Parent), @"\s+", " ");
        SetupApiDeviceRelations.Apply([child], [Evidence(flat)]);
        Assert.Equal(Parent, child.ParentDeviceInstanceId);
        child.ParentDeviceInstanceId = "";
        var closed = flat.Replace("dvi: Parent Device:", "dvi: {Install Device - exit(0x00000000)} dvi: Parent Device:", StringComparison.Ordinal);
        SetupApiDeviceRelations.Apply([child], [Evidence(closed)]);
        Assert.Empty(child.ParentDeviceInstanceId);
    }

    private static string Section(string child, string parent) => $$"""
        >>>  [Device Install (Hardware initiated) - {{child}}]
        >>>  Section start 2026/09/17 15:41:28.262
             dvi: {Install Device - {{child}}} 15:41:28.278
             dvi: Device Status: 0x01802400
             dvi: Parent Device: {{parent}}
        <<<  Section end 2026/09/17 15:41:29.000
        """;
}
