namespace UsbForensicAudit;

/// <summary>
/// Доменный флаг активной корпоративной USB-защиты (DLP). Значение заполняется на старте
/// приложения из инфраструктурного детектора; домен только читает его при формировании
/// пояснений к статусу устройства и не зависит от WMI/реестра.
/// </summary>
public static class EndpointProtectionState
{
    private static int _isProtectionActive;

    public static bool IsProtectionActive
    {
        get => Volatile.Read(ref _isProtectionActive) != 0;
        set => Volatile.Write(ref _isProtectionActive, value ? 1 : 0);
    }
}
