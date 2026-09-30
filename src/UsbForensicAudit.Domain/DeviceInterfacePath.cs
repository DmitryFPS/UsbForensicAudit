namespace UsbForensicAudit;

/// <summary>Сопоставление символической ссылки с известным ID, без угадывания разделителей модели.</summary>
public static class DeviceInterfacePath
{
    public static bool Matches(string symbolicLink, string instanceId)
    {
        var link = symbolicLink;
        if (link.StartsWith("##?#", StringComparison.Ordinal) || link.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            link = link[4..];
        }
        else
        {
            return false;
        }
        var suffix = link.LastIndexOf('#');
        if (suffix <= 0 || !Guid.TryParse(link[(suffix + 1)..], out _))
        {
            return false;
        }
        // Windows кодирует и '\\', и '/' как '#'. Обратное преобразование неоднозначно.
        return link[..suffix].Equals(instanceId.Replace('\\', '#').Replace('/', '#'), StringComparison.OrdinalIgnoreCase);
    }
}
