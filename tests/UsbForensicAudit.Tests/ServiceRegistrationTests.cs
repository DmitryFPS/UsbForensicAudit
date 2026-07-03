using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Проверяет, что DI-контейнер собирает те же зависимости, что и монолит до рефакторинга
/// (критично для сохранения поведения в рантайме).
/// </summary>
public sealed class ServiceRegistrationTests
{
    [Fact]
    public void TimelineEnricher_uses_wmi_connected_device_probe_from_di()
    {
        var services = new ServiceCollection();
        services.AddApplicationServices();
        services.AddInfrastructureServices();

        using var provider = services.BuildServiceProvider();
        var enricher = provider.GetRequiredService<TimelineEnricher>();

        var probeField = typeof(TimelineEnricher).GetField(
            "_connectedDeviceProbe",
            BindingFlags.Instance | BindingFlags.NonPublic);

        Assert.NotNull(probeField);
        Assert.IsType<WmiConnectedDeviceProbe>(probeField.GetValue(enricher));
    }

    [Fact]
    public void AuditOrchestrator_evidence_collectors_preserve_scan_pipeline_order()
    {
        var services = new ServiceCollection();
        services.AddApplicationServices();
        services.AddInfrastructureServices();

        using var provider = services.BuildServiceProvider();
        var collectors = provider.GetServices<IEvidenceCollector>().ToList();

        Assert.Equal(
            new[]
            {
                typeof(SetupApiLogCollector),
                typeof(EventLogCollector),
                typeof(EndpointProtectionEventLogCollector),
                typeof(UserArtifactCollector),
                typeof(OfflineHiveCollector),
                typeof(ExecutionArtifactCollector),
                typeof(ProcessAttributionCollector),
            },
            collectors.Select(x => x.GetType()).ToArray());
    }
}
