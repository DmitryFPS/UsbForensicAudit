namespace UsbForensicAudit;

/// <summary>
/// Доменный флаг активной корпоративной USB-защиты (DLP). Значение заполняется на старте
/// приложения из инфраструктурного детектора; домен только читает его при формировании
/// пояснений к статусу устройства и не зависит от WMI/реестра.
/// </summary>
public static class EndpointProtectionState
{
    public static bool IsProtectionActive { get; set; }
}
