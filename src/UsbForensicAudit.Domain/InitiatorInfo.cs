namespace UsbForensicAudit;

public readonly record struct InitiatorInfo(string Kind, string Account, string? Sid)
{
    public static InitiatorInfo Unknown { get; } = new("Unknown", "не определено", null);

    public string DisplayText => Kind switch
    {
        "System" => $"Система ({Account})",
        "Administrator" => $"Администратор ({Account})",
        "User" => $"Пользователь ({Account})",
        _ => "Не определено"
    };
}
