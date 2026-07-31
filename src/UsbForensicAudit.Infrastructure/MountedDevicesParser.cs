using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

public static class MountedDevicesParser
{
    private static readonly Regex DriveNameRegex = new(
        @"^\\DosDevices\\(?<drive>[A-Z]:)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex VolumeNameRegex = new(
        @"Volume\{(?<guid>[0-9A-F-]{36})\}",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly byte[] GptPrefix = Encoding.ASCII.GetBytes("DMIO:ID:");

    public static VolumeIdentity Parse(string valueName, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(valueName);
        ArgumentNullException.ThrowIfNull(data);

        var identity = new VolumeIdentity
        {
            MappingName = valueName,
            Source = "Registry: MountedDevices",
            Confidence = "Medium",
            Provenance = [$@"HKLM\SYSTEM\MountedDevices value '{valueName}'"]
        };

        var drive = DriveNameRegex.Match(valueName);
        if (drive.Success)
        {
            identity.DriveLetter = drive.Groups["drive"].Value.ToUpperInvariant();
        }

        var volume = VolumeNameRegex.Match(valueName);
        if (volume.Success && Guid.TryParse(volume.Groups["guid"].Value, out var volumeGuid))
        {
            identity.VolumeGuid = volumeGuid.ToString("D").ToUpperInvariant();
        }

        if (TryReadUtf16Path(data, out var path))
        {
            var instancePath = NormalizeDeviceInstancePath(path);
            identity.DevicePath = instancePath;
            identity.Confidence = "High";
            identity.Provenance.Add("MountedDevices UTF-16 device path");
            if (!instancePath.Equals(path, StringComparison.Ordinal))
            {
                identity.Provenance.Add($"Raw MountedDevices value: {path}");
            }

            return identity;
        }

        if (TryReadGptId(data, out var diskId))
        {
            identity.DiskId = diskId;
            identity.Confidence = "High";
            identity.Provenance.Add("MountedDevices GPT DMIO identifier");
            return identity;
        }

        if (TryReadMbr(data, out var signature, out var offset))
        {
            identity.DiskSignature = signature;
            identity.PartitionOffset = offset;
            identity.Confidence = "High";
            identity.Provenance.Add("MountedDevices MBR signature and partition offset");
            return identity;
        }

        identity.Confidence = "Low";
        identity.Provenance.Add($"Unrecognized binary mapping ({data.Length} bytes)");
        return identity;
    }

    public static bool TryReadUtf16Path(byte[] data, out string path)
    {
        path = "";
        if (data.Length < 6 || data.Length % 2 != 0)
        {
            return false;
        }

        var candidate = Encoding.Unicode.GetString(data).TrimEnd('\0').Trim();

        // Съёмные носители Windows записывает в экранированной форме _??_USBSTOR#...
        // Без этого префикса значение не распознавалось и буква диска не связывалась
        // с носителем.
        if (!(candidate.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase)
              || candidate.StartsWith("_??_", StringComparison.OrdinalIgnoreCase)
              || candidate.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase)
              || candidate.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)
              || candidate.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        if (candidate.Any(c => char.IsControl(c) && c is not '\t'))
        {
            return false;
        }

        path = candidate;
        return true;
    }

    /// <summary>
    /// Приводит значение вида _??_USBSTOR#Disk&amp;Ven_...#SERIAL&amp;0#{GUID интерфейса}
    /// к идентификатору экземпляра USBSTOR\Disk&amp;Ven_...\SERIAL&amp;0, по которому
    /// том связывается с записью устройства из Enum.
    /// </summary>
    public static string NormalizeDeviceInstancePath(string path)
    {
        if (!path.StartsWith("_??_", StringComparison.OrdinalIgnoreCase)
            && !path.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
        {
            return path;
        }

        var value = path[4..].Replace('#', '\\');
        var segments = value.Split('\\', StringSplitOptions.RemoveEmptyEntries).ToList();
        if (segments.Count > 1
            && segments[^1].StartsWith('{')
            && segments[^1].EndsWith('}')
            && Guid.TryParse(segments[^1], out _))
        {
            segments.RemoveAt(segments.Count - 1);
        }

        return segments.Count == 0 ? path : string.Join('\\', segments);
    }

    public static bool TryReadMbr(byte[] data, out string diskSignature, out long partitionOffset)
    {
        diskSignature = "";
        partitionOffset = 0;
        if (data.Length != 12)
        {
            return false;
        }

        var signature = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0, 4));
        var offset = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(4, 8));
        if (signature == 0 || offset == 0 || offset > long.MaxValue)
        {
            return false;
        }

        diskSignature = signature.ToString("X8");
        partitionOffset = (long)offset;
        return true;
    }

    public static bool TryReadGptId(byte[] data, out string diskId)
    {
        diskId = "";
        if (data.Length != GptPrefix.Length + 16 || !data.AsSpan(0, GptPrefix.Length).SequenceEqual(GptPrefix))
        {
            return false;
        }

        var guid = new Guid(data.AsSpan(GptPrefix.Length, 16));
        if (guid == Guid.Empty)
        {
            return false;
        }

        diskId = guid.ToString("D").ToUpperInvariant();
        return true;
    }
}
