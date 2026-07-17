using System.Text;

namespace UsbForensicAudit;

public static class DevicePathNormalizer
{
    public static string NormalizeDeviceId(string? value, bool replaceHashes = false)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        var source = value.Trim().Trim('{', '}');
        var builder = new StringBuilder(source.Length);
        var previousWasSeparator = false;
        foreach (var character in source)
        {
            var current = replaceHashes && character == '#' ? '\\' : character;
            if (current == '\\')
            {
                if (previousWasSeparator)
                {
                    continue;
                }

                previousWasSeparator = true;
            }
            else
            {
                previousWasSeparator = false;
            }

            builder.Append(current);
        }

        return builder.ToString();
    }

    public static string CanonicalDeviceId(string? value, bool replaceHashes = false) =>
        NormalizeDeviceId(value, replaceHashes).ToUpperInvariant();
}
