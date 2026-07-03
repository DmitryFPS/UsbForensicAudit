namespace UsbForensicAudit;

/// <summary>
/// Порт живой трассировки реестра по VID/PID (ветки, которые читают сторонние USB-утилиты).
/// Реализация обращается к реестру и живёт в инфраструктуре; Application зависит от абстракции.
/// </summary>
public interface IExternalUtilityRegistryTracer
{
    IReadOnlyList<ExternalUtilitySourceHit> Trace(string? vid, string? pid);
}
