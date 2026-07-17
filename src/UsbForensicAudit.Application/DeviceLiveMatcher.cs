namespace UsbForensicAudit;

public static class DeviceLiveMatcher
{
    private static readonly char[] ModelTokenSeparators = [' ', '_', '-'];

    public static string NormalizePnpId(string? value) =>
        DevicePathNormalizer.CanonicalDeviceId(value, replaceHashes: true);

    public static bool PnpIdsMatch(string? left, string? right) =>
        NormalizePnpId(left).Length > 0
        && NormalizePnpId(left) == NormalizePnpId(right);

    public static bool AreLikelySameDevice(UsbDeviceRecord left, UsbDeviceRecord right)
    {
        if (PnpIdsMatch(left.DeviceInstanceId, right.DeviceInstanceId))
        {
            return true;
        }

        if (HasSharedContainer(left, right))
        {
            return true;
        }

        if (CompatibleVidPid(left, right) && SameHardwareSerial(left, right))
        {
            return true;
        }

        if (ScsiInstancesMatch(left, right))
        {
            return true;
        }

        return SameDiskModel(left, right);
    }

    public static bool ScsiInstancesMatch(UsbDeviceRecord left, UsbDeviceRecord right)
    {
        var leftSignature = ParseScsiSignature(left.DeviceInstanceId);
        var rightSignature = ParseScsiSignature(right.DeviceInstanceId);
        return leftSignature.Length > 0
               && leftSignature.Equals(rightSignature, StringComparison.OrdinalIgnoreCase);
    }

    public static string ParseScsiSignature(string? deviceInstanceId)
    {
        var normalized = NormalizePnpId(deviceInstanceId);
        if (!normalized.StartsWith(@"SCSI\", StringComparison.Ordinal))
        {
            return "";
        }

        var parts = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3 || !parts[1].StartsWith("DISK&", StringComparison.Ordinal))
        {
            return "";
        }

        return $"{parts[1]}\\{parts[2]}";
    }

    public static bool SameDiskModel(UsbDeviceRecord left, UsbDeviceRecord right)
    {
        if (!left.DeviceInstanceId.StartsWith(@"SCSI\", StringComparison.OrdinalIgnoreCase)
            || !right.DeviceInstanceId.StartsWith(@"SCSI\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var leftModel = NormalizeModelToken(left);
        var rightModel = NormalizeModelToken(right);
        return leftModel.Length >= 8
               && leftModel.Equals(rightModel, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeModelToken(UsbDeviceRecord device)
    {
        foreach (var candidate in new[]
                 {
                     device.FriendlyName,
                     device.Product,
                     ParseScsiProduct(device.DeviceInstanceId)
                 })
        {
            var normalized = NormalizeModelName(candidate);
            if (normalized.Length >= 8)
            {
                return normalized;
            }
        }

        return "";
    }

    private static string ParseScsiProduct(string? deviceInstanceId)
    {
        var normalized = NormalizePnpId(deviceInstanceId);
        var diskPart = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(x => x.StartsWith("DISK&", StringComparison.Ordinal));
        if (string.IsNullOrWhiteSpace(diskPart))
        {
            return "";
        }

        var prod = diskPart.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(x => x.StartsWith("PROD_", StringComparison.Ordinal));
        return prod is null ? "" : prod["PROD_".Length..].Replace('_', ' ');
    }

    private static string NormalizeModelName(string? value)
    {
        var tokens = (value ?? "").Split(ModelTokenSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Join(' ', tokens.Where(x => x.Length > 0));
    }

    private static bool HasSharedContainer(UsbDeviceRecord left, UsbDeviceRecord right)
    {
        if (string.IsNullOrWhiteSpace(left.ContainerId)
            || string.IsNullOrWhiteSpace(right.ContainerId))
        {
            return false;
        }

        if (left.ContainerId.Equals("{00000000-0000-0000-ffff-ffffffffffff}", StringComparison.OrdinalIgnoreCase)
            || right.ContainerId.Equals("{00000000-0000-0000-ffff-ffffffffffff}", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return left.ContainerId.Equals(right.ContainerId, StringComparison.OrdinalIgnoreCase);
    }

    private static bool CompatibleVidPid(UsbDeviceRecord left, UsbDeviceRecord right)
    {
        return (string.IsNullOrWhiteSpace(left.Vid) || string.IsNullOrWhiteSpace(right.Vid)
                || left.Vid.Equals(right.Vid, StringComparison.OrdinalIgnoreCase))
               && (string.IsNullOrWhiteSpace(left.Pid) || string.IsNullOrWhiteSpace(right.Pid)
                   || left.Pid.Equals(right.Pid, StringComparison.OrdinalIgnoreCase));
    }

    private static bool SameHardwareSerial(UsbDeviceRecord left, UsbDeviceRecord right)
    {
        if (!DeviceIdentityGraph.IsHardwareSerial(left.Serial)
            || !DeviceIdentityGraph.IsHardwareSerial(right.Serial))
        {
            return false;
        }

        return DeviceIdentityGraph.NormalizeSerial(left.Serial)
            .Equals(DeviceIdentityGraph.NormalizeSerial(right.Serial), StringComparison.OrdinalIgnoreCase);
    }
}
