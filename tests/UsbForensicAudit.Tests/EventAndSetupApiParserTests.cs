using System.Globalization;
using System.IO;
using Xunit;

namespace UsbForensicAudit.Tests;

public sealed class EventAndSetupApiParserTests
{
    [Fact]
    public void ParsesKernelPnpXmlStructurallyWithoutLocalizedMessage()
    {
        var xml = EventXml(
            "Microsoft-Windows-Kernel-PnP",
            "Microsoft-Windows-Kernel-PnP/Configuration",
            410,
            ("DeviceInstanceId", @"USB\VID_1234&PID_5678\SERIAL01"));

        Assert.True(EventLogRecordParser.TryParse(xml, out var parsed));
        var evidence = EventLogRecordParser.ToEvidence(parsed!, "Локализованное описание без ключевых слов");

        Assert.NotNull(evidence);
        Assert.Equal(@"USB\VID_1234&PID_5678\SERIAL01", evidence!.DeviceHint);
        Assert.Equal("Microsoft-Windows-Kernel-PnP", evidence.Provider);
        Assert.Equal(77, evidence.RecordId);
        Assert.Equal("HOST01", evidence.Computer);
        Assert.Equal(DateTimeOffset.Parse("2026-07-11T07:00:00Z"), evidence.TimestampUtc);
    }

    [Fact]
    public void ClassifiesSecurity6416ByProviderAndId()
    {
        var xml = EventXml(
            "Microsoft-Windows-Security-Auditing",
            "Security",
            6416,
            ("DeviceId", @"USBSTOR\DISK&VEN_TEST\ABC"));

        Assert.True(EventLogRecordParser.TryParse(xml, out var parsed));
        var evidence = EventLogRecordParser.ToEvidence(parsed!);

        Assert.Equal("Подключение/распознавание устройства", evidence!.EvidenceCategory);
    }

    [Theory]
    [InlineData("Microsoft-Windows-Partition", "Microsoft-Windows-Partition/Diagnostic", 1006, @"STORAGE\Volume\ABC")]
    [InlineData("Microsoft-Windows-Storage-ClassPnP", "Microsoft-Windows-Storage-ClassPnP/Operational", 507, @"SCSI\Disk&Ven_USB_UASP\ABC")]
    [InlineData("Microsoft-Windows-WPD-MTPClassDriver", "Microsoft-Windows-WPD-MTPClassDriver/Operational", 1001, "MTP device")]
    public void SupportsPartitionStorageAndMtpProviders(string provider, string channel, int id, string device)
    {
        Assert.True(EventLogRecordParser.TryParse(EventXml(provider, channel, id, ("DeviceId", device)), out var parsed));

        var evidence = EventLogRecordParser.ToEvidence(parsed!);

        Assert.NotNull(evidence);
        Assert.Contains("Подключение", evidence!.EvidenceCategory);
    }

    [Fact]
    public void DoesNotIncludeInternalDiskFromGenericWords()
    {
        var xml = EventXml(
            "Microsoft-Windows-Kernel-PnP",
            "System",
            410,
            ("DeviceName", "Internal disk device"));

        Assert.True(EventLogRecordParser.TryParse(xml, out var parsed));
        Assert.Null(EventLogRecordParser.ToEvidence(parsed!));
    }

    [Fact]
    public void ParsesOneSetupApiRecordPerTimedSectionAndKeepsRawText()
    {
        var text = """
                   >>>  [Device Install (Hardware initiated) - SCSI\Disk&Ven_USB&Prod_UASP\123]
                   >>>  Section start 2026/07/11 10:15:20.125
                        cmd: "C:\Windows\system32\mmc.exe"
                        dvi: Device Instance ID: SCSI\Disk&Ven_USB&Prod_UASP\123
                   <<<  Section end 2026/07/11 10:15:20.500
                   >>>  [Device Install - USB\VID_DEAD&PID_BEEF\NO_TIME]
                        dvi: no valid section timestamp
                   <<<  Section end
                   """;

        var records = SetupApiLogParser.Parse(
            new StringReader(text),
            "setupapi.dev.log.old",
            @"C:\Windows\INF\setupapi.dev.log.old");

        var record = Assert.Single(records);
        Assert.Equal("setupapi.dev.log.old", record.Source);
        Assert.Equal(@"C:\Windows\INF\setupapi.dev.log.old", record.SourceFile);
        Assert.Contains(@"SCSI\Disk&Ven_USB&Prod_UASP\123", record.DeviceHint);
        Assert.Contains("cmd:", record.RawText);
        Assert.Equal(TimeZoneInfo.ConvertTimeToUtc(
            DateTime.Parse("2026-07-11 10:15:20.125", CultureInfo.InvariantCulture)), record.TimestampUtc.UtcDateTime);
    }

    [Theory]
    [InlineData(@"USBSTOR\Disk&Ven_Test\A")]
    [InlineData(@"STORAGE\Volume\A")]
    [InlineData(@"SWD\WPDBUSENUM\A")]
    [InlineData(@"USB4\ROOT_DEVICE\A")]
    public void SetupApiSupportsDeviceFamilies(string deviceId)
    {
        var text = $"""
                    >>>  [Device Install - {deviceId}]
                    >>>  Section start 2026/07/11 10:15:20.125
                         dvi: Device Instance ID: {deviceId}
                    <<<  Section end
                    """;

        Assert.Single(SetupApiLogParser.Parse(new StringReader(text), "setupapi.dev.log"));
    }

    [Fact]
    public void CapAlwaysProducesExplicitWarning()
    {
        var warnings = new List<string>();

        EventLogRetentionPolicy.AddCapWarning(warnings, "test-channel", 5000);

        Assert.Single(warnings);
        Assert.Contains("5000", warnings[0]);
        Assert.Contains("лимит", warnings[0], StringComparison.OrdinalIgnoreCase);
    }

    private static string EventXml(
        string provider,
        string channel,
        int eventId,
        params (string Name, string Value)[] fields)
    {
        var data = string.Join(
            "",
            fields.Select(field =>
                $"<Data Name=\"{System.Security.SecurityElement.Escape(field.Name)}\">{System.Security.SecurityElement.Escape(field.Value)}</Data>"));
        return $"""
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                  <System>
                    <Provider Name="{provider}" />
                    <EventID>{eventId}</EventID>
                    <EventRecordID>77</EventRecordID>
                    <TimeCreated SystemTime="2026-07-11T07:00:00.0000000Z" />
                    <Channel>{channel}</Channel>
                    <Computer>HOST01</Computer>
                  </System>
                  <EventData>{data}</EventData>
                </Event>
                """;
    }
}
