using System.Globalization;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class FiveDeviceRegressionTests
{
    private const string Disk = @"USBSTOR\Disk&Ven_Kingston&Prod_SNA-DC/U&Rev_1.08\454147455432303139303232&0";
    private const string Link = "##?#USBSTOR#Disk&Ven_Kingston&Prod_SNA-DC#U&Rev_1.08#454147455432303139303232&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
    private const string TracePath = @"HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\" + Link;

    [Fact]
    public void Real_disk_model_with_slash_is_a_valid_pnp_target_and_enum_trace()
    {
        Assert.True(DeviceRemovalPolicy.IsInstanceId(Disk));
        var path = @"HKLM\SYSTEM\ControlSet002\Enum\" + Disk;
        Assert.Equal(Disk, DeviceTracePolicy.EnumInstanceId(path));
        Assert.NotNull(DeviceTracePolicy.NormalizePath(path));
        var node = new DeviceRemovalNode(Disk, "USB disk", false, Service: "disk");
        Assert.Empty(DeviceRemovalPolicy.ProtectionReason(node, [node]));
    }

    [Fact]
    public void Interface_reuses_real_enum_identity_instead_of_inventing_a_four_part_id()
    {
        var parsed = UsbRegistryForensicHelpers.ParseWpdIdentity(Link, [Disk]);
        Assert.Equal(Disk, parsed.DeviceInstanceId);
        Assert.Equal("454147455432303139303232", parsed.Serial);
        var records = new List<UsbDeviceRecord>
        {
            new() { DeviceInstanceId = Disk, Serial = parsed.Serial, Service = "disk" },
            new() { DeviceInstanceId = parsed.DeviceInstanceId, Serial = parsed.Serial, DeviceType = "DeviceInterface" }
        };
        DeviceIdentityGraph.Process(records);
        Assert.Equal(records[0].CanonicalDeviceId, records[1].CanonicalDeviceId);
    }

    [Fact]
    public void Known_wpd_wrapper_preserves_its_backing_disk_with_slash_in_model()
    {
        var wrapper = @"SWD\WPDBUSENUM\_??_" + Disk;
        var link = "##?#" + wrapper.Replace('\\', '#').Replace('/', '#')
            + "#{6ac27878-a6fa-4155-ba85-f98f491d4f33}";
        var parsed = UsbRegistryForensicHelpers.ParseWpdIdentity(link, [wrapper]);
        Assert.Equal(wrapper, parsed.DeviceInstanceId);
        Assert.Equal(Disk, parsed.BackingDeviceInstanceId);
        Assert.Equal("454147455432303139303232", parsed.Serial);
    }

    [Fact]
    public void Ambiguous_encoded_interface_is_not_assigned_to_an_arbitrary_instance()
    {
        var collision = Disk.Replace("SNA-DC/U", "SNA-DC#U");
        Assert.True(DeviceInterfacePath.Matches(Link, collision));
        Assert.Empty(UsbRegistryForensicHelpers.ParseWpdIdentity(Link, [Disk, collision]).DeviceInstanceId);
        var trace = Assert.IsType<DeviceRegistryTrace>(DeviceTracePolicy.Bind(TracePath,
            new UsbDeviceRecord { DeviceInstanceId = Disk, Service = "disk" }, "fingerprint"));
        Assert.NotEmpty(DeviceTracePolicy.ProtectionReason(trace,
            [new(Disk, "first", false, Service: "disk"), new(collision, "second", false, Service: "disk")], _ => false));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Interface_deletion_checks_the_actual_disk_and_blocks_reconnection(bool connected)
    {
        var record = new UsbDeviceRecord { DeviceInstanceId = Disk, Service = "disk" };
        var trace = Assert.IsType<DeviceRegistryTrace>(DeviceTracePolicy.Bind(TracePath, record, "fingerprint"));
        Assert.Equal(Disk.ToUpperInvariant(), Assert.Single(trace.DeviceIds));
        var node = new DeviceRemovalNode(Disk, "USB disk", connected, Service: "disk");
        var reason = DeviceTracePolicy.ProtectionReason(trace, [node], _ => connected);
        Assert.Equal(connected, reason.Length > 0);
        Assert.Null(DeviceTracePolicy.Bind(TracePath, new UsbDeviceRecord { DeviceInstanceId = Disk.Replace("454147455432303139303232", "OTHER123456") }, "fingerprint"));
    }

    [Theory]
    [InlineData("E6E9701F-BBFC-11F1-989F-183D2D302099}#0000000000004400")]
    [InlineData("{E6E9701F-BBFC-11F1-989F-183D2D302099}#0000000000004400")]
    [InlineData(@"{E6E9701F-BBFC-11F1-989F-183D2D302099}\0000000000004400")]
    public void Windows_volume_identity_is_never_a_hardware_serial(string serial)
    {
        Assert.False(DeviceIdentityGraph.IsHardwareSerial(serial));
        Assert.Equal("не указан (ID Windows)", UserDisplayText.Serial(serial));
        var records = new[]
        {
            new UsbDeviceRecord { DeviceInstanceId = Disk, Serial = "454147455432303139303232", CanonicalDeviceId = "ONE", IsCanonicalPrimary = true },
            new UsbDeviceRecord { DeviceInstanceId = @"SWD\WPDBUSENUM\" + serial, Serial = serial, CanonicalDeviceId = "ONE" }
        };
        var groups = new DevicePhysicalGrouping();
        groups.Reset(records);
        var group = Assert.IsType<DeviceDisplayGroup>(groups.GroupNameFromItem(records[0], 0, CultureInfo.InvariantCulture));
        Assert.DoesNotContain("E6E9701F", group.Description);
        Assert.Contains("S/N 454147455432303139303232", group.Description);
    }

    [Theory]
    [InlineData("USBSTOR", "")]
    [InlineData("WUDFWpdFs", @"wpdbusenum\fs; USB\Class_08&SubClass_06&Prot_50")]
    public void Storage_evidence_takes_precedence_over_wpd_catalogue_metadata(string service, string compatible)
    {
        var record = new UsbDeviceRecord
        {
            DeviceInstanceId = @"USB\VID_11B0&PID_6298\454147455432303139303232",
            Service = service,
            CompatibleIds = compatible,
            DeviceType = "Portable/MTP",
            RawJson = "WPDBUSENUM"
        };
        DeviceTransportClassifier.Classify(record);
        Assert.Equal("MSC/USBSTOR", record.Transport);
        Assert.Equal(DeviceKindResolver.Storage, record.DeviceKind);
    }

    [Fact]
    public void Real_mtp_phone_is_not_reclassified_as_mass_storage()
    {
        var phone = new UsbDeviceRecord { DeviceInstanceId = @"USB\VID_04E8&PID_6860\PHONE123", Service = "WUDFWpdMtp", CompatibleIds = "MTP" };
        DeviceTransportClassifier.Classify(phone);
        Assert.Equal("MTP/PTP/WPD", phone.Transport);
        Assert.Equal(DeviceKindResolver.PortableDevice, phone.DeviceKind);
    }

    [Fact]
    public void Old_disconnect_is_preserved_as_evidence_but_not_presented_as_the_latest_session_end()
    {
        var old = new DateTimeOffset(2026, 9, 28, 8, 52, 29, TimeSpan.Zero);
        var device = new UsbDeviceRecord { DeviceInstanceId = Disk, VisualCategory = "RealUsb" };
        var scan = new AuditResult
        {
            Devices = [device],
            Evidence =
        [
            Event(old.AddHours(-1), "Подключение USB"),
            Event(old, "Отключение USB"),
            Event(old.AddDays(1), "Подключение USB")
        ]
        };
        new TimelineEnricher().Enrich(scan);
        Assert.Equal(old, device.LastDisconnectedUtc);
        Assert.Equal("PreviousSession", device.DisconnectDisplayKind);
        Assert.Contains("неизвестно", device.LastDisconnectedText);
        Assert.Contains(device.Sessions, session => session.EndUtc == old);
    }

    private static EvidenceRecord Event(DateTimeOffset at, string category) => new()
    {
        TimestampUtc = at,
        Source = "Kernel-PnP",
        DeviceHint = Disk,
        EvidenceCategory = category,
        CanEstablishConnectionDate = true
    };
}
