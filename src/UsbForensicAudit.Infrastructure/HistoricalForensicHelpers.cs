using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace UsbForensicAudit;

internal static partial class HistoricalForensicHelpers
{
    internal const string TransactionLogsPresentNotReplayed = "TransactionLogsPresentNotReplayed";

    internal static IReadOnlyList<string> DeviceMigrationPaths() =>
    [
        @"SYSTEM\Setup\Upgrade\PnP\CurrentControlSet\Control\DeviceMigration\Devices",
        @"SYSTEM\CurrentControlSet\Control\DeviceMigration\Devices"
    ];

    internal static bool TryParseLastPresentDate(object? value, out DateTimeOffset timestamp) =>
        UsbRegistryForensicHelpers.TryParseFileTime(value, out timestamp);

    internal static ControlSetSelection ParseSelect(IReadOnlyDictionary<string, object?> values)
    {
        static int? Number(IReadOnlyDictionary<string, object?> source, string name)
        {
            if (!source.TryGetValue(name, out var value) || value is null)
            {
                return null;
            }

            try
            {
                return Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture);
            }
            catch
            {
                return null;
            }
        }

        return new ControlSetSelection(
            FormatControlSet(Number(values, "Current")),
            FormatControlSet(Number(values, "Default")),
            FormatControlSet(Number(values, "LastKnownGood")));
    }

    internal static IReadOnlyList<ControlSetDifference> CompareControlSets(
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyCollection<string>>> snapshots,
        ControlSetSelection selection)
    {
        if (string.IsNullOrWhiteSpace(selection.Current)
            || !snapshots.TryGetValue(selection.Current, out var current))
        {
            return [];
        }

        var differences = new List<ControlSetDifference>();
        foreach (var (controlSet, areas) in snapshots)
        {
            if (controlSet.Equals(selection.Current, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var (area, identities) in areas)
            {
                var currentIdentities = current.TryGetValue(area, out var found)
                    ? found
                    : Array.Empty<string>();
                foreach (var identity in identities.Except(currentIdentities, StringComparer.OrdinalIgnoreCase))
                {
                    differences.Add(new ControlSetDifference(
                        controlSet,
                        selection.Current,
                        area,
                        identity,
                        controlSet.Equals(selection.Default, StringComparison.OrdinalIgnoreCase),
                        controlSet.Equals(selection.LastKnownGood, StringComparison.OrdinalIgnoreCase)));
                }
            }
        }

        return differences
            .OrderBy(x => x.Area, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Identity, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    internal static OfflineHistoricalPaths BuildOfflinePaths(string root)
    {
        var fullRoot = Path.GetFullPath(root);
        var windows = Path.GetFileName(fullRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
            .Equals("Windows", StringComparison.OrdinalIgnoreCase)
            ? fullRoot
            : Path.Combine(fullRoot, "Windows");
        return new OfflineHistoricalPaths(
            windows,
            Path.Combine(windows, "INF"),
            Path.Combine(windows, "System32", "config", "SYSTEM"),
            Path.Combine(windows, "System32", "config", "SOFTWARE"));
    }

    internal static string GetTransactionLogStatus(string hivePath)
    {
        return File.Exists(hivePath + ".LOG1") || File.Exists(hivePath + ".LOG2")
            ? TransactionLogsPresentNotReplayed
            : "TransactionLogsAbsent";
    }

    internal static bool TryParseShadowDevicePath(string? value, out string path)
    {
        path = "";
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var candidate = value.Trim().TrimEnd('\\');
        if (!ShadowPathRegex().IsMatch(candidate))
        {
            return false;
        }

        path = candidate + "\\";
        return true;
    }

    internal static string SnapshotDedupKey(string sourceSha256, string identity) =>
        $"{sourceSha256.Trim().ToUpperInvariant()}|{identity.Trim().ToUpperInvariant()}";

    internal static string ComputeSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string FormatControlSet(int? number) =>
        number is >= 0 and <= 999 ? $"ControlSet{number.Value:000}" : "";

    [GeneratedRegex(@"^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ShadowPathRegex();
}

internal sealed record ControlSetSelection(string Current, string Default, string LastKnownGood);

internal sealed record ControlSetDifference(
    string SourceControlSet,
    string CurrentControlSet,
    string Area,
    string Identity,
    bool SourceIsDefault,
    bool SourceIsLastKnownGood);

internal sealed record OfflineHistoricalPaths(
    string WindowsDirectory,
    string InfDirectory,
    string SystemHive,
    string SoftwareHive);
