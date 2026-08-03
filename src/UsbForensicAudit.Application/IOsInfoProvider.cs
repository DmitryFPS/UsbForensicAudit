namespace UsbForensicAudit;

/// <summary>
/// Порт получения сведений об установке операционной системы.
/// Реализация живёт в инфраструктуре (реестр Windows); Domain и Application
/// зависят только от абстракции и остаются свободными от Microsoft.Win32.
/// </summary>
public interface IOsInfoProvider
{
    /// <summary>Дата установки ОС (UTC) или null, если её не удалось определить.</summary>
    DateTimeOffset? GetInstalledAtUtc();
}

/// <summary>
/// Заглушка для контекстов без доступа к системным сведениям (юнит-тесты,
/// запуск вне Windows): дата установки считается неизвестной.
/// </summary>
public sealed class NullOsInfoProvider : IOsInfoProvider
{
    public DateTimeOffset? GetInstalledAtUtc() => null;
}
