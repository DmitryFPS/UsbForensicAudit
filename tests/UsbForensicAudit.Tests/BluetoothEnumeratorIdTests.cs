using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// На шине Bluetooth лежат вперемешку сами сопряжённые устройства и их услуги.
/// Раньше вкладка называла внешним устройством каждую услугу, и один телефон
/// давал полтора десятка строк «Внешнее устройство» с непонятными именами.
/// </summary>
public class BluetoothEnumeratorIdTests
{
    private const string PairedPhone = @"BTHENUM\Dev_887598C2F5F2\7&2768a9f8&0&BluetoothDevice_887598C2F5F2";

    private const string PhonebookService =
        @"BTHENUM\{0000112f-0000-1000-8000-00805f9b34fb}_VID&00010075_PID&0100\7&2768a9f8&0&887598C2F5F2_C00000000";

    [Fact]
    public void Service_of_a_paired_device_is_told_apart_from_the_device()
    {
        Assert.True(BluetoothEnumeratorId.IsServiceRecord(PhonebookService));
        Assert.False(BluetoothEnumeratorId.IsPairedDeviceRecord(PhonebookService));

        Assert.True(BluetoothEnumeratorId.IsPairedDeviceRecord(PairedPhone));
        Assert.False(BluetoothEnumeratorId.IsServiceRecord(PairedPhone));
    }

    [Fact]
    public void Identifier_of_the_service_is_read_from_the_record()
    {
        Assert.True(BluetoothEnumeratorId.TryReadServiceUuid(PhonebookService, out var uuid));
        Assert.Equal("{0000112f-0000-1000-8000-00805f9b34fb}", uuid);
    }

    [Fact]
    public void Records_of_other_buses_are_left_alone()
    {
        Assert.False(BluetoothEnumeratorId.IsServiceRecord(@"USB\VID_ABCD&PID_1234\2412242109410569603146"));
        Assert.False(BluetoothEnumeratorId.IsPairedDeviceRecord(@"USBSTOR\Disk&Ven_Generic\7&1"));
        Assert.False(BluetoothEnumeratorId.IsServiceRecord(""));
    }

    /// <summary>
    /// Услуга — это возможность соединения, а не принесённая вещь. Само же
    /// сопряжённое устройство кто-то принёс, и оно остаётся внешним.
    /// </summary>
    [Fact]
    public void Tab_counts_the_phone_but_not_its_services()
    {
        var service = new UsbDeviceRecord { DeviceInstanceId = PhonebookService };
        var phone = new UsbDeviceRecord { DeviceInstanceId = PairedPhone };

        Assert.Equal(DeviceExternality.BusInfrastructure, DeviceExternality.Resolve(service));
        Assert.False(service.IsExternalDevice);

        Assert.Equal(DeviceExternality.ExternalPeripheral, DeviceExternality.Resolve(phone));
        Assert.True(phone.IsExternalDevice);
    }

    [Fact]
    public void Reader_is_told_what_a_service_record_means()
    {
        Assert.Equal(
            "Часть устройства или шины, а не отдельное устройство",
            DeviceExternality.Describe(DeviceExternality.BusInfrastructure));
    }
}
