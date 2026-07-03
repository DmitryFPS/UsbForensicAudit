namespace UsbForensicAudit;

internal static class ProcmonRegistryPathClassifier
{
    public sealed record Classification(string Title, bool IsDirectSource, bool IsIndirectSource, int Rank);

    public static Classification Classify(string registryPath)
    {
        var path = registryPath.Replace('/', '\\');

        if (path.Contains(@"\Enum\USBSTOR", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\USBSTOR\", StringComparison.OrdinalIgnoreCase))
        {
            return new Classification("Enum\\USBSTOR", IsDirectSource: true, IsIndirectSource: false, Rank: 100);
        }

        if (path.Contains(@"\CurrentControlSet\Enum\USB\", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\Enum\USB\", StringComparison.OrdinalIgnoreCase))
        {
            return new Classification("Enum\\USB", IsDirectSource: true, IsIndirectSource: false, Rank: 95);
        }

        if (path.Contains(@"\MountedDevices", StringComparison.OrdinalIgnoreCase))
        {
            return new Classification("MountedDevices", IsDirectSource: false, IsIndirectSource: true, Rank: 80);
        }

        if (path.Contains(@"\MountPoints2", StringComparison.OrdinalIgnoreCase))
        {
            return new Classification("MountPoints2", IsDirectSource: false, IsIndirectSource: true, Rank: 75);
        }

        if (path.Contains(@"\Windows Portable Devices\Devices", StringComparison.OrdinalIgnoreCase))
        {
            return new Classification("WPD Devices", IsDirectSource: true, IsIndirectSource: false, Rank: 70);
        }

        if (path.Contains(@"OpenSavePidlMRU", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"RecentDocs", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"LastVisitedPidlMRU", StringComparison.OrdinalIgnoreCase))
        {
            return new Classification("MRU пользователя", IsDirectSource: false, IsIndirectSource: true, Rank: 60);
        }

        if (path.Contains(@"\CurrentControlSet\Control\DeviceClasses", StringComparison.OrdinalIgnoreCase))
        {
            return new Classification("DeviceClasses", IsDirectSource: false, IsIndirectSource: true, Rank: 55);
        }

        return new Classification("Реестр Windows", IsDirectSource: false, IsIndirectSource: true, Rank: 40);
    }
}
