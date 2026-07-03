namespace UsbForensicAudit;

/// <summary>
/// Категории доказательств корпоративного контроля USB. Единый источник названий для сборщика
/// журналов (инфраструктура) и логики построения таймлайна (Application).
/// </summary>
public static class EndpointProtectionCategories
{
    public const string Connect = "Контроль USB: подключение устройства";
    public const string Disconnect = "Контроль USB: отключение устройства";
}
