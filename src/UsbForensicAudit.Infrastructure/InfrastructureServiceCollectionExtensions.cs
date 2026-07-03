using Microsoft.Extensions.DependencyInjection;

namespace UsbForensicAudit;

/// <summary>
/// Регистрация инфраструктурных реализаций портов слоя Application: сборщики, хранилище,
/// WMI/реестр-адаптеры и сервисы мониторинга/отчётов.
/// </summary>
public static class InfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructureServices(this IServiceCollection services)
    {
        services.AddSingleton<IConnectedDeviceProbe, WmiConnectedDeviceProbe>();
        services.AddSingleton<IExternalUtilityRegistryTracer, RegistryExternalUtilityTracer>();
        services.AddSingleton<IPrivilegeChecker, WindowsPrivilegeChecker>();
        services.AddSingleton<IAuditStorage, AuditStorage>();
        services.AddSingleton<ILiveDeviceMerger, LiveDeviceMerger>();
        services.AddSingleton<IUsbDeviceCollector, UsbRegistryCollector>();

        // Порядок регистрации сборщиков доказательств задаёт порядок шагов сканирования.
        services.AddSingleton<IEvidenceCollector, SetupApiLogCollector>();
        services.AddSingleton<IEvidenceCollector, EventLogCollector>();
        services.AddSingleton<IEvidenceCollector, EndpointProtectionEventLogCollector>();
        services.AddSingleton<IEvidenceCollector, UserArtifactCollector>();
        services.AddSingleton<IEvidenceCollector, OfflineHiveCollector>();
        services.AddSingleton<IEvidenceCollector, ExecutionArtifactCollector>();
        services.AddSingleton<IEvidenceCollector, ProcessAttributionCollector>();

        services.AddSingleton<IReportService, ReportService>();
        services.AddSingleton<WmiUsbMonitor>();
        services.AddSingleton<LiveUsbSnapshotService>();
        return services;
    }
}
