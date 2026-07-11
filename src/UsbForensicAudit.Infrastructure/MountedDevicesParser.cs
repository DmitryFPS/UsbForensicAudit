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
            identity.DevicePath = path;
            identity.Confidence = "High";
            identity.Provenance.Add("MountedDevices UTF-16 device path");
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
        if (!(candidate.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase)
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
