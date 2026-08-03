using System.Linq;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Число внешних устройств должно быть ОДИНАКОВЫМ во всех местах, где оно
/// показывается: вкладка «Обзор» и отчёты (руководителю, HTML-сводка). Раньше
/// Обзор считал по сырому result.Devices, а отчёты — по USB-охвату ListedDevices,
/// и цифры расходились (8 против 7). Единый источник — ExternalListedDevices.
/// </summary>
public sealed class DeviceCountConsistencyTests
{
    private static AuditResult MixedResult()
    {
        var result = new AuditResult();

        // Реальный USB-носитель — попадает и в Обзор, и в отчёт.
        result.Devices.Add(new UsbDeviceRecord
        {
            DeviceKind = DeviceKindResolver.Storage,
            VisualCategory = "RealUsb",
            Transport = "MSC/USBSTOR",
            Serial = "USB-1",
            DeviceInstanceId = @"USBSTOR\Disk&Ven\USB-1",
            CanonicalDeviceId = "canon-usb-1"
        });

        // Ещё один внешний носитель.
        result.Devices.Add(new UsbDeviceRecord
        {
            DeviceKind = DeviceKindResolver.Storage,
            VisualCategory = "RealUsb",
            Transport = "MSC/USBSTOR",
            Serial = "USB-2",
            DeviceInstanceId = @"USBSTOR\Disk&Ven\USB-2",
            CanonicalDeviceId = "canon-usb-2"
        });

        return result;
    }

    [Fact]
    public void Overview_and_report_count_external_devices_identically()
    {
        var result = MixedResult();

        // Источник «Обзора» (после фикла — тот же хелпер).
        var overview = ForensicReportContext.ExternalListedDevices(result.Devices).Count;

        // Источник отчётов: ListedDevices, отфильтрованные по IsExternalDevice.
        var ctx = ForensicReportContext.Create(result);
        var report = ctx.ListedDevices.Count(x => x.IsExternalDevice);

        Assert.Equal(report, overview);
    }

    [Fact]
    public void Helper_returns_only_external_scoped_devices()
    {
        var result = MixedResult();

        var external = ForensicReportContext.ExternalListedDevices(result.Devices);

        Assert.NotEmpty(external);
        Assert.All(external, d => Assert.True(d.IsExternalDevice));
    }
}
