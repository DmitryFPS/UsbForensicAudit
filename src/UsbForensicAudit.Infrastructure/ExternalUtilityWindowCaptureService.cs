using System.Diagnostics;

namespace UsbForensicAudit;

public static class ExternalUtilityWindowCaptureService
{
    public static ExternalUtilityCapture Capture(RunningExternalUtility utility)
    {
        if (utility.UtilityId == "usboblivion")
        {
            throw new InvalidOperationException(
                "USB Oblivion не показывает таблицу результатов в окне. " +
                "Следы запуска и очистки смотрите на вкладке «Следы очистки», " +
                "а отдельные строки можно разобрать через «Разобрать вставку».");
        }

        Process? process = null;
        try
        {
            process = Process.GetProcessById(utility.ProcessId);
            process.Refresh();

            if (process.HasExited)
            {
                throw new InvalidOperationException(
                    $"Процесс «{utility.DisplayName}» уже завершён. Запустите утилиту снова и повторите считывание.");
            }

            var hwnd = process.MainWindowHandle;
            if (hwnd == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    $"Окно «{utility.DisplayName}» не найдено. Разверните окно утилиты на экране и повторите считывание.");
            }

            if (utility.UtilityId == "usbdetector")
            {
                Win32WindowHelper.PrepareUsbDetectorCapture(hwnd);
            }

            var handles = Win32ControlEnumerator.FindListViews(hwnd)
                .OrderBy(Win32WindowHelper.GetWindowTop)
                .ThenBy(handle => handle.ToInt64())
                .ToArray();

            var snapshots = ReadSnapshots(handles, hwnd, utility, allowClipboard: false);

            if (utility.UtilityId == "usbdetector"
                && !snapshots.Any(x => Win32ListViewReader.IsOtherTracesTable(x)))
            {
                Win32WindowHelper.PrepareUsbDetectorCapture(hwnd);
                snapshots = MergeWithClipboardFallback(handles, hwnd, utility, snapshots);
            }

            snapshots = snapshots.Where(IsRelevantListViewSnapshot).ToList();

            if (snapshots.Count == 0)
            {
                if (process.HasExited)
                {
                    throw new InvalidOperationException(
                        $"Утилита «{utility.DisplayName}» закрылась при считывании. Запустите её снова, выполните поиск в окне и повторите.");
                }

                throw new InvalidOperationException(
                    $"В окне «{utility.DisplayName}» не найдены таблицы со строками. Выполните поиск в утилите и повторите.");
            }

            var sections = new List<ExternalUtilitySection>();
            for (var index = 0; index < snapshots.Count; index++)
            {
                var snapshot = snapshots[index];
                var title = ResolveSectionTitle(utility.UtilityId, index, snapshots.Count, snapshot);
                sections.Add(new ExternalUtilitySection
                {
                    Title = title,
                    ColumnHeaders = snapshot.Headers,
                    Rows = BuildRows(utility.DisplayName, title, snapshot)
                });
            }

            return new ExternalUtilityCapture
            {
                UtilityId = utility.UtilityId,
                DisplayName = utility.DisplayName,
                ProcessId = utility.ProcessId,
                WindowTitle = process.MainWindowTitle,
                CapturedAtUtc = DateTimeOffset.UtcNow,
                Sections = sections
            };
        }
        finally
        {
            process?.Dispose();
        }
    }

    private static List<Win32ListViewReader.ListViewSnapshot> ReadSnapshots(
        IReadOnlyList<IntPtr> handles,
        IntPtr mainWindow,
        RunningExternalUtility utility,
        bool allowClipboard)
    {
        return handles
            .Select(handle => Win32ListViewReader.ReadForCapture(
                handle,
                utility.ProcessId,
                mainWindow,
                utility.UtilityId,
                allowClipboard))
            .Where(IsRelevantListViewSnapshot)
            .ToList();
    }

    private static List<Win32ListViewReader.ListViewSnapshot> MergeWithClipboardFallback(
        IReadOnlyList<IntPtr> handles,
        IntPtr mainWindow,
        RunningExternalUtility utility,
        IReadOnlyList<Win32ListViewReader.ListViewSnapshot> silentSnapshots)
    {
        var merged = silentSnapshots.ToList();

        foreach (var handle in handles.OrderByDescending(Win32WindowHelper.GetWindowTop))
        {
            var silent = silentSnapshots.FirstOrDefault(x => x.Handle == handle);
            if (silent is not null && Win32ListViewReader.IsOtherTracesTable(silent))
            {
                continue;
            }

            var withClipboard = Win32ListViewReader.ReadForCapture(
                handle,
                utility.ProcessId,
                mainWindow,
                utility.UtilityId,
                allowClipboard: true);

            if (!IsRelevantListViewSnapshot(withClipboard))
            {
                continue;
            }

            if (silent is null)
            {
                merged.Add(withClipboard);
                continue;
            }

            if (Win32ListViewReader.IsOtherTracesTable(withClipboard)
                || withClipboard.Rows.Count > silent.Rows.Count)
            {
                merged.Remove(silent);
                merged.Add(withClipboard);
            }
        }

        return merged
            .OrderBy(x => x.Top)
            .ThenBy(x => x.Handle.ToInt64())
            .ToList();
    }

    private static string ResolveSectionTitle(
        string utilityId,
        int index,
        int total,
        Win32ListViewReader.ListViewSnapshot snapshot)
    {
        if (utilityId == "usbdetector")
        {
            if (Win32ListViewReader.IsOtherTracesTable(snapshot))
            {
                return ExternalUtilitySectionCatalog.OtherTracesSection;
            }

            if (Win32ListViewReader.IsMainRegistryTable(snapshot))
            {
                return ExternalUtilitySectionCatalog.MainRegistrySection;
            }

            if (total >= 2 && index == 0)
            {
                return ExternalUtilitySectionCatalog.MainRegistrySection;
            }

            if (total >= 2 && index == 1)
            {
                return ExternalUtilitySectionCatalog.OtherTracesSection;
            }

            return ExternalUtilitySectionCatalog.MainRegistrySection;
        }

        if (total == 1)
        {
            return "Список устройств";
        }

        var headerHint = string.Join(' ', snapshot.Headers).ToUpperInvariant();
        if (headerHint.Contains("VID") && headerHint.Contains("PID"))
        {
            return "Другие следы / дополнительный список";
        }

        return $"Таблица {index + 1}";
    }

    private static bool IsRelevantListViewSnapshot(Win32ListViewReader.ListViewSnapshot snapshot)
    {
        if (snapshot.Rows.Count == 0)
        {
            return false;
        }

        if (Win32ListViewReader.IsOtherTracesTable(snapshot))
        {
            return true;
        }

        var headerText = string.Join(' ', snapshot.Headers);
        string[] usbHeaders =
        [
            "VID", "PID", "UID", "Производитель", "Manufacturer",
            "Device Name", "Модель", "Model", "Description", "Предназначение", "Носитель"
        ];

        if (usbHeaders.Any(header => headerText.Contains(header, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        var sample = string.Join(' ', snapshot.Rows.Take(5).SelectMany(x => x)).ToUpperInvariant();
        if (sample.Contains("VID") || sample.Contains("PID") || sample.Contains("USB\\"))
        {
            return true;
        }

        if (snapshot.Rows.Any(row => row.Any(cell =>
                ExternalUtilityIdentifierParser.TryParseHexId(cell, out _))))
        {
            return true;
        }

        if (snapshot.Headers.Count <= 1
            && snapshot.Rows.All(row => row.Count <= 1 && (row.FirstOrDefault()?.Contains(":\\") ?? false))
            && !sample.Contains("USB"))
        {
            return false;
        }

        return snapshot.Headers.Count >= 2;
    }

    private static IReadOnlyList<ExternalUtilityRow> BuildRows(
        string utilityName,
        string sectionTitle,
        Win32ListViewReader.ListViewSnapshot snapshot)
    {
        var rows = new List<ExternalUtilityRow>();
        var headers = ExternalUtilityColumnNormalizer.NormalizeHeaders(snapshot.Headers);

        foreach (var cells in snapshot.Rows)
        {
            var values = ExternalUtilityColumnNormalizer.MapRowValues(headers, cells);

            rows.Add(new ExternalUtilityRow
            {
                SectionTitle = sectionTitle,
                UtilityName = utilityName,
                Values = values,
                PrimaryText = BuildPrimaryText(values)
            });
        }

        return rows;
    }

    private static string BuildPrimaryText(IReadOnlyDictionary<string, string> values)
    {
        foreach (var key in new[] { "UID", "VID", "Device Name", "Description", "Имя устройства", "Производитель", "Manufacturer", "Модель", "Model" })
        {
            if (values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return values.Values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "Запись";
    }
}
