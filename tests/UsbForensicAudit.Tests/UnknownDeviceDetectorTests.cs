using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Тесты детектора неизвестных устройств: сравнение live-снимка с базовой
/// линией из доказательной базы. Ключевое свойство — асимметрия правил:
/// устройство с аппаратным серийником узнаётся только по серийнику,
/// без серийника — по VID+PID.
/// </summary>
public sealed class UnknownDeviceDetectorTests
{
    private static readonly KnownDeviceIdentity KnownFlash =
        new("0951", "1666", "AA11BB22CC33", @"USB\VID_0951&PID_1666\AA11BB22CC33");

    private static readonly KnownDeviceIdentity KnownHub =
        new("05E3", "0610", "5&2E60F146&0&3", @"USB\VID_05E3&PID_0610\5&2E60F146&0&3");

    private static LiveUsbDevice Live(string deviceId, string vid = "", string pid = "", string name = "device")
    {
        return new LiveUsbDevice
        {
            DeviceId = deviceId,
            Vid = vid,
            Pid = pid,
            DeviceName = name,
            StableKey = LiveDeviceIdentity.StableKey(deviceId, vid, pid)
        };
    }

    [Fact]
    public void Known_device_with_matching_serial_is_not_reported()
    {
        var detector = new UnknownDeviceDetector([KnownFlash]);

        var unknown = detector.DetectNew([Live(@"USB\VID_0951&PID_1666\AA11BB22CC33", "0951", "1666")]);

        Assert.Empty(unknown);
    }

    [Fact]
    public void Same_model_with_different_serial_is_reported()
    {
        // Другая флешка той же модели — другое физическое устройство.
        var detector = new UnknownDeviceDetector([KnownFlash]);

        var unknown = detector.DetectNew([Live(@"USB\VID_0951&PID_1666\ZZ99YY88XX77", "0951", "1666")]);

        Assert.Single(unknown);
    }

    [Fact]
    public void Device_without_hardware_serial_matches_by_vid_pid()
    {
        // У хабов серийника нет (генерируемый instance-id с амперсандами):
        // сравнение опускается до VID+PID, иначе каждый порт давал бы алерт.
        var detector = new UnknownDeviceDetector([KnownHub]);

        var unknown = detector.DetectNew([Live(@"USB\VID_05E3&PID_0610\5&11223344&0&4", "05E3", "0610")]);

        Assert.Empty(unknown);
    }

    [Fact]
    public void Completely_new_device_is_reported_once()
    {
        var detector = new UnknownDeviceDetector([KnownFlash]);
        var stranger = Live(@"USB\VID_ABCD&PID_1234\STRANGER01", "ABCD", "1234", "Neizvestnaya fleshka");

        var first = detector.DetectNew([stranger]);
        var second = detector.DetectNew([stranger]);

        Assert.Single(first);
        Assert.Empty(second);
    }

    [Fact]
    public void Device_known_only_by_instance_path_is_not_reported()
    {
        // Съёмные тома и виртуальные узлы DLP-фильтров не имеют VID/PID —
        // последний рубеж сопоставления по полному пути экземпляра.
        var known = new KnownDeviceIdentity("", "", "", @"SWD\WPDBUSENUM\{A1B2C3}#0000000000000000");
        var detector = new UnknownDeviceDetector([known]);

        var unknown = detector.DetectNew([Live(@"SWD\WPDBUSENUM\{A1B2C3}#0000000000000000")]);

        Assert.Empty(unknown);
    }

    [Fact]
    public void Serial_known_from_source_without_vid_pid_still_matches()
    {
        // MountedDevices и WPD дают серийник без VID/PID: устройство с тем же
        // серийником — то же устройство, даже если VID/PID пришли только из live.
        var known = new KnownDeviceIdentity("", "", "AA11BB22CC33", "");
        var detector = new UnknownDeviceDetector([known]);

        var unknown = detector.DetectNew([Live(@"USB\VID_0951&PID_1666\AA11BB22CC33", "0951", "1666")]);

        Assert.Empty(unknown);
    }

    [Fact]
    public void Normalized_serial_with_ampersand_zero_suffix_matches()
    {
        // USBSTOR добавляет к серийнику суффикс "&0" — нормализация обязана его срезать.
        var known = new KnownDeviceIdentity("0951", "1666", "AA11BB22CC33&0", @"USBSTOR\Disk\AA11BB22CC33&0");
        var detector = new UnknownDeviceDetector([known]);

        var unknown = detector.DetectNew([Live(@"USB\VID_0951&PID_1666\AA11BB22CC33", "0951", "1666")]);

        Assert.Empty(unknown);
    }

    [Fact]
    public void Empty_baseline_reports_everything()
    {
        var detector = new UnknownDeviceDetector([]);

        Assert.Equal(0, detector.BaselineSize);
        Assert.Single(detector.DetectNew([Live(@"USB\VID_0951&PID_1666\AA11BB22CC33", "0951", "1666")]));
    }

    [Fact]
    public void Multiple_devices_in_one_snapshot_are_split_correctly()
    {
        var detector = new UnknownDeviceDetector([KnownFlash, KnownHub]);

        var unknown = detector.DetectNew(
        [
            Live(@"USB\VID_0951&PID_1666\AA11BB22CC33", "0951", "1666", "known flash"),
            Live(@"USB\VID_05E3&PID_0610\5&778899&0&1", "05E3", "0610", "known hub"),
            Live(@"USB\VID_DEAD&PID_BEEF\EVIL42", "DEAD", "BEEF", "stranger")
        ]);

        var single = Assert.Single(unknown);
        Assert.Equal("stranger", single.DeviceName);
    }
}
