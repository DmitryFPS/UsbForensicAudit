namespace UsbForensicAudit;

public sealed class DeviceRemovalService(IDeviceRemovalPlatform platform)
{
    private readonly SemaphoreSlim _operation = new(1, 1);

    public DeviceRemovalPlan Preview(AuditResult result, IEnumerable<UsbDeviceRecord> selection)
    {
        if (result.IsOfflineSource || !result.ComputerName.Equals(platform.ComputerName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Удаление доступно только для сканирования этого компьютера. Выполните новое локальное сканирование.");
        }
        var selected = selection.Distinct().ToArray();
        if (selected.Length == 0 || selected.Any(x => !result.Devices.Contains(x)))
        {
            throw new InvalidOperationException("Выберите записи из текущего результата сканирования.");
        }
        var inventory = platform.ReadInventory();
        var items = new List<DeviceRemovalItem>();
        foreach (var record in selected)
        {
            if (DeviceComposition.IsVolumeMetadata(record) || record.DeviceType.Equals("USBFlags", StringComparison.OrdinalIgnoreCase))
            {
                items.Add(Protected(record, "Общая запись тома или модели, а не отдельный экземпляр Windows."));
                continue;
            }
            var sources = result.Devices.Where(x => ReferenceEquals(x, record)
                || (!string.IsNullOrWhiteSpace(record.CanonicalDeviceId)
                    && x.CanonicalDeviceId.Equals(record.CanonicalDeviceId, StringComparison.OrdinalIgnoreCase)));
            var matches = sources.SelectMany(source => inventory.Where(node =>
                    Normalize(node.InstanceId) == Normalize(source.DeviceInstanceId)
                    || (node.AuditInstanceId.Length > 0 && Normalize(node.AuditInstanceId) == Normalize(source.DeviceInstanceId))))
                .DistinctBy(x => x.InstanceId, StringComparer.OrdinalIgnoreCase).ToArray();
            if (matches.Length == 0)
            {
                items.Add(Protected(record, "Исторический след: соответствующего экземпляра в текущей Windows нет."));
                continue;
            }
            foreach (var node in matches)
            {
                var related = DeviceRemovalPolicy.Related(node, inventory);
                var reason = DeviceRemovalPolicy.ProtectionReason(node, related);
                items.Add(new(node.InstanceId, string.IsNullOrWhiteSpace(node.Name) ? record.DisplayName : node.Name,
                    reason.Length == 0, reason, node, related.Select(x => x.InstanceId).ToArray()));
            }
        }
        return new(platform.ComputerName, result.SessionId, DateTimeOffset.UtcNow,
            items.DistinctBy(x => x.InstanceId, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    public async Task<DeviceRemovalResult> ExecuteAsync(DeviceRemovalPlan plan, IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (!await _operation.WaitAsync(0, cancellationToken))
        {
            throw new InvalidOperationException("Удаление уже выполняется.");
        }
        try
        {
            platform.EnsureRemovalSupported();
            if (!plan.ComputerName.Equals(platform.ComputerName, StringComparison.OrdinalIgnoreCase)
                || plan.SessionId.StartsWith("offline-", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("План относится к другому компьютеру или офлайн-источнику.");
            }
            var targets = plan.Items.Where(x => x.CanRemove).DistinctBy(x => x.InstanceId, StringComparer.OrdinalIgnoreCase).ToArray();
            if (targets.Length == 0)
            {
                throw new InvalidOperationException("В плане нет доступных для удаления экземпляров.");
            }
            var inventory = platform.ReadInventory();
            foreach (var target in targets)
            {
                var error = ValidateCurrent(target, inventory);
                if (error.Length > 0)
                {
                    throw new InvalidOperationException($"{target.Name}: {error} Повторите предварительную проверку.");
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report("Сохранение копий выбранных записей Windows...");
            var backupDirectory = await platform.BackupAsync(plan, cancellationToken);
            var outcomes = new List<DeviceRemovalOutcome>();
            foreach (var target in targets)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    outcomes.Add(new(target.InstanceId, target.Name, "Cancelled", "Отменено до запуска команды Windows."));
                    continue;
                }
                DeviceRemovalOutcome outcome;
                try
                {
                    var error = ValidateCurrent(target, platform.ReadInventory());
                    if (error.Length > 0)
                    {
                        outcome = new(target.InstanceId, target.Name, "Blocked", error);
                    }
                    else if (!platform.InstanceExists(target.InstanceId) && !platform.IsPresent(target.InstanceId))
                    {
                        outcome = new(target.InstanceId, target.Name, "AlreadyAbsent", "Экземпляр уже отсутствует.");
                    }
                    else
                    {
                        progress?.Report($"Удаление отключённого экземпляра: {target.Name}");
                        var command = await platform.RemoveAsync(target.InstanceId);
                        var gone = !platform.InstanceExists(target.InstanceId) && !platform.IsPresent(target.InstanceId);
                        outcome = command.ExitCode == 0 && gone
                            ? new(target.InstanceId, target.Name, "Removed", "Отсутствие экземпляра подтверждено после удаления.")
                            : new(target.InstanceId, target.Name, "Failed",
                                $"Windows: код {command.ExitCode}. {(gone ? "" : "Запись осталась или устройство подключено. ")}{command.Output}");
                    }
                }
                catch (Exception ex)
                {
                    outcome = new(target.InstanceId, target.Name, "Failed", ex.Message);
                }
                outcomes.Add(outcome);
                progress?.Report($"{outcome.Name}: {outcome.Detail}");
                // Сохраняем результат каждого шага, а не только всего пакета.
                await platform.SaveResultAsync(backupDirectory, new(backupDirectory, outcomes.ToArray()));
            }
            var result = new DeviceRemovalResult(backupDirectory, outcomes);
            await platform.SaveResultAsync(backupDirectory, result);
            return result;
        }
        finally
        {
            _operation.Release();
        }
    }

    private string ValidateCurrent(DeviceRemovalItem target, IReadOnlyList<DeviceRemovalNode> inventory)
    {
        if (!DeviceRemovalPolicy.IsInstanceId(target.InstanceId) || target.Identity is null
            || !target.Identity.InstanceId.Equals(target.InstanceId, StringComparison.OrdinalIgnoreCase))
        {
            return "Некорректный ID экземпляра.";
        }
        var node = inventory.SingleOrDefault(x => x.InstanceId.Equals(target.InstanceId, StringComparison.OrdinalIgnoreCase));
        if (node is null)
        {
            return platform.InstanceExists(target.InstanceId) || platform.IsPresent(target.InstanceId)
                ? "Состояние экземпляра не удалось подтвердить." : "";
        }
        var related = DeviceRemovalPolicy.Related(node, inventory);
        var reason = DeviceRemovalPolicy.ProtectionReason(node, related);
        if (reason.Length > 0)
        {
            return reason;
        }
        if (!SameIdentity(node, target.Identity)
            || related.Any(x => !target.RelatedInstanceIds.Contains(x.InstanceId, StringComparer.OrdinalIgnoreCase)))
        {
            return "Состав или идентификаторы устройства изменились после предварительной проверки.";
        }
        return related.Any(x => platform.IsPresent(x.InstanceId))
            ? "Устройство или его компонент подключены после проверки." : "";
    }

    private static bool SameIdentity(DeviceRemovalNode a, DeviceRemovalNode b) =>
        a.ContainerId.Equals(b.ContainerId, StringComparison.OrdinalIgnoreCase)
        && a.Service.Equals(b.Service, StringComparison.OrdinalIgnoreCase)
        && a.ClassGuid.Equals(b.ClassGuid, StringComparison.OrdinalIgnoreCase)
        && a.HardwareIds.Equals(b.HardwareIds, StringComparison.OrdinalIgnoreCase)
        && a.ParentIdPrefix.Equals(b.ParentIdPrefix, StringComparison.OrdinalIgnoreCase);

    private static string Normalize(string id) => DeviceRemovalPolicy.NormalizeInstanceId(id);
    private static DeviceRemovalItem Protected(UsbDeviceRecord device, string reason) =>
        new(device.DeviceInstanceId, device.DisplayName, false, reason, null, []);
}
