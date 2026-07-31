using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

public class DeviceMarkerTextTests
{
    [Theory]
    [InlineData("WAN Miniport (PPTP)", "PTP", false)]
    [InlineData("WAN Miniport (PTP)", "PTP", true)]
    [InlineData("Camera PTP driver", "PTP", true)]
    [InlineData("POCO M6 Pro MTP", "MTP", true)]
    [InlineData("SMTPSVC", "MTP", false)]
    [InlineData(@"SWD\WPDBUSENUM\device", "WPD", false)]
    [InlineData(@"Device WPD\node", "WPD", true)]
    [InlineData("SDXC card reader", "SD", false)]
    [InlineData(@"SD\VID_1234", "SD", true)]
    public void Short_acronyms_match_only_as_whole_words(string text, string marker, bool expected)
    {
        Assert.Equal(expected, DeviceMarkerText.ContainsWord(text, marker));
    }

    [Fact]
    public void Long_markers_still_match_as_substrings()
    {
        Assert.True(DeviceMarkerText.ContainsMarker(@"SWD\WPDBUSENUM\_??_USBSTOR", "WPDBUSENUM"));
        Assert.True(DeviceMarkerText.ContainsMarker("Storage is REMOVABLE_MEDIA", "REMOVABLE"));
    }

    [Fact]
    public void Pptp_network_adapter_is_not_a_portable_device()
    {
        Assert.False(DeviceTransportClassifier.IsRelevantLiveCandidate(
            @"ROOT\MS_PPTPMINIPORT\0000",
            service: "RasPptp",
            name: "WAN Miniport (PPTP)"));
    }
}
