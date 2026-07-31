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
        services.AddSingleton<IReferenceImageDetector, WindowsReferenceImageDetector>();
        services.AddSingleton<IAuditStorage, AuditStorage>();
        services.AddSingleton<ILiveDeviceMerger, LiveDeviceMerger>();
        services.AddSingleton<IUsbDeviceCollector, UsbRegistryCollector>();
        services.AddSingleton<IHistoricalArtifactCollector, HistoricalArtifactCollector>();
        services.AddSingleton<IFileSystemChangeCollector, FileChangeJournalCollector>();

        // Порядок регистрации сборщиков доказательств задаёт порядок шагов сканирования.
        services.AddSingleton<IEvidenceCollector, SetupApiLogCollector>();
        services.AddSingleton<IEvidenceCollector, EventLogCollector>();
        services.AddSingleton<IEvidenceCollector, EndpointProtectionEventLogCollector>();
        services.AddSingleton<IEvidenceCollector, UserArtifactCollector>();
        services.AddSingleton<IEvidenceCollector, OfflineHiveCollector>();
        services.AddSingleton<IEvidenceCollector, ExecutionArtifactCollector>();
        services.AddSingleton<IEvidenceCollector, ProcessAttributionCollector>();

        // Сетевые связи собираются отдельным семейством сборщиков: у каждой связи
        // своя история сеансов и свои обращения, и в один список доказательств
        // они не укладываются.
        services.AddSingleton<INetworkArtifactCollector, NetworkProfileCollector>();
        services.AddSingleton<INetworkArtifactCollector, NetworkEventLogCollector>();
        services.AddSingleton<INetworkArtifactCollector, NetworkShareArtifactCollector>();
        services.AddSingleton<INetworkArtifactCollector, BluetoothArtifactCollector>();
        services.AddSingleton<INetworkArtifactCollector, BrowserHistoryCollector>();

        services.AddSingleton<INetworkEnvironmentService, NetworkEnvironmentService>();
        services.AddSingleton<IReportService, ReportService>();
        services.AddSingleton<WmiUsbMonitor>();
        services.AddSingleton<LiveUsbSnapshotService>();
        return services;
    }
}
