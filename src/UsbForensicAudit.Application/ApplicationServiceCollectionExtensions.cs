using Microsoft.Extensions.DependencyInjection;

namespace UsbForensicAudit;

/// <summary>
/// Регистрация сервисов слоя Application (use cases и доменные сервисы обработки).
/// </summary>
public static class ApplicationServiceCollectionExtensions
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        services.AddSingleton<CorrelationService>();
        services.AddSingleton<CleanupDetector>();
        services.AddSingleton<TimelineEnricher>();
        services.AddSingleton<AuditOrchestrator>();
        return services;
    }
}
