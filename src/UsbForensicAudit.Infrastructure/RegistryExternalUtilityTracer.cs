namespace UsbForensicAudit;

/// <summary>
/// Инфраструктурный адаптер порта <see cref="IExternalUtilityRegistryTracer"/> над
/// статическим трассировщиком реестра.
/// </summary>
public sealed class RegistryExternalUtilityTracer : IExternalUtilityRegistryTracer
{
    public IReadOnlyList<ExternalUtilitySourceHit> Trace(string? vid, string? pid)
        => ExternalUtilityRegistrySourceTracer.Trace(vid, pid);
}
