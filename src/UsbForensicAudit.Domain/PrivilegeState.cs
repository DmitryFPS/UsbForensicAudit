namespace UsbForensicAudit;

/// <summary>
/// Права, с которыми фактически выполняется сканирование. Права администратора
/// сами по себе не открывают ветки Enum, чей список доступа их не разрешает:
/// нужна включённая привилегия SeBackupPrivilege, и по умолчанию она выключена.
/// </summary>
public sealed record PrivilegeState(
    bool IsAdministrator,
    bool IsLocalSystem,
    bool BackupPrivilegeEnabled,
    bool RestorePrivilegeEnabled)
{
    public string BackupPrivilegeError { get; init; } = "";

    /// <summary>
    /// Полный доступ к реестру. Без него часть веток недоступна и отчёт неполон.
    /// </summary>
    public bool CanReadProtectedRegistry => IsLocalSystem || BackupPrivilegeEnabled;

    public string Describe()
    {
        if (!IsAdministrator && !IsLocalSystem)
        {
            return "Сканирование выполняется без прав администратора. Ветки Enum, журналы Windows "
                   + "и теневые копии недоступны — отчёт заведомо неполон.";
        }

        if (IsLocalSystem)
        {
            return "Сканирование выполняется под учётной записью SYSTEM: доступны все ветки реестра.";
        }

        if (BackupPrivilegeEnabled)
        {
            return "Сканирование выполняется от администратора с включённой привилегией "
                   + "SeBackupPrivilege: защищённые ветки реестра доступны.";
        }

        var reason = string.IsNullOrWhiteSpace(BackupPrivilegeError) ? "" : $" ({BackupPrivilegeError})";
        return "Сканирование выполняется от администратора, но включить SeBackupPrivilege не удалось"
               + reason
               + ". Ветки, чей список доступа не разрешает чтение администратору, будут пропущены, "
               + "и отсутствие устройства в отчёте не будет означать, что его не подключали.";
    }
}
