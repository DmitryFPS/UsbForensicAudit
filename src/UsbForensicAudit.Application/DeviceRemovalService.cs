namespace UsbForensicAudit;

public sealed class DeviceRemovalService(IDeviceRemovalPlatform platform, IAuditStorage? storage = null)
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
        var databaseRecords = new List<DeviceRemovalDatabaseRecord>();
        foreach (var record in selected)
        {
            var artifact = DeviceComposition.IsVolumeMetadata(record) || record.DeviceType.Equals("USBFlags", StringComparison.OrdinalIgnoreCase);
            var sources = result.Devices.Where(x => ReferenceEquals(x, record)
                || (!string.IsNullOrWhiteSpace(record.DeviceInstanceId)
                    && x.DeviceInstanceId.Equals(record.DeviceInstanceId, StringComparison.OrdinalIgnoreCase))
                || (!artifact && !string.IsNullOrWhiteSpace(record.CanonicalDeviceId)
                    && x.CanonicalDeviceId.Equals(record.CanonicalDeviceId, StringComparison.OrdinalIgnoreCase))).ToArray();
            var before = items.Count;
            if (platform is IRegistryTracePlatform registry)
            {
                foreach (var source in sources)
                {
                    foreach (var path in DeviceTracePolicy.SourcePaths(source))
                    {
                        string? fingerprint;
                        try { fingerprint = registry.ReadTraceFingerprint(path); }
                        catch (Exception ex) when (ex is UnauthorizedAccessException or System.IO.IOException or System.Security.SecurityException)
                        {
                            items.Add(new(path, source.DisplayName, false, "Не удалось прочитать запись: " + ex.Message, null, []));
                            continue;
                        }
                        if (fingerprint is null || DeviceTracePolicy.Bind(path, source, fingerprint) is not { } trace)
                        {
                            continue;
                        }

                        var reason = DeviceTracePolicy.ProtectionReason(trace, inventory, platform.IsPresent);
                        var name = source.DisplayName + (trace.Vid.Length > 0 ? " — общий кэш модели" : " — история Windows");
                        items.Add(new(path, name, reason.Length == 0, reason, null, trace.DeviceIds, trace));
                    }
                }
            }
            var identifiers = (artifact ? [] : sources).SelectMany(source => new[] { source.DeviceInstanceId }.Concat(source.IdentityAliases))
                .Select(Normalize).Where(x => x.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var matches = inventory.Where(node => identifiers.Contains(Normalize(node.InstanceId))
                    || (node.AuditInstanceId.Length > 0 && identifiers.Contains(Normalize(node.AuditInstanceId))))
                .DistinctBy(x => x.InstanceId, StringComparer.OrdinalIgnoreCase).ToArray();
            if (matches.Length == 0)
            {
                if (items.Count == before)
                {
                    items.Add(Protected(record, "Нет поддерживаемой записи в текущей Windows. Карточка останется в базе."));
                }
            }
            foreach (var node in matches)
            {
                var related = DeviceRemovalPolicy.Related(node, inventory);
                var reason = DeviceRemovalPolicy.ProtectionReason(node, related);
                items.Add(new(node.InstanceId, string.IsNullOrWhiteSpace(node.Name) ? record.DisplayName : node.Name,
                    reason.Length == 0, reason, node, related.Select(x => x.InstanceId).ToArray()));
            }
            var targetIds = items.Skip(before).Select(x => x.InstanceId).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            databaseRecords.AddRange(sources.Select(source => new DeviceRemovalDatabaseRecord(source.DeviceInstanceId, targetIds)));
        }
        return new(platform.ComputerName, result.SessionId, DateTimeOffset.UtcNow,
            items.GroupBy(x => x.InstanceId, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.FirstOrDefault(x => !x.CanRemove) ?? group.First()).ToArray())
        { DatabaseRecords = databaseRecords };
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
            var targets = plan.Items.Where(x => x.CanRemove).DistinctBy(x => x.InstanceId, StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x.Trace is null ? 0 : 1).ToArray();
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
            var protocolError = "";
            foreach (var target in targets)
            {
                if (protocolError.Length > 0)
                {
                    outcomes.Add(new(target.InstanceId, target.Name, "NotAttempted", "Не запущено: не удалось сохранить протокол предыдущего шага."));
                    continue;
                }
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
                    else if (IsAbsent(target))
                    {
                        outcome = new(target.InstanceId, target.Name, "AlreadyAbsent", "Экземпляр уже отсутствует.");
                    }
                    else
                    {
                        progress?.Report($"Удаление отключённого экземпляра: {target.Name}");
                        var command = target.Trace is { } trace
                            ? await ((IRegistryTracePlatform)platform).RemoveTraceAsync(trace)
                            : await platform.RemoveAsync(target.InstanceId);
                        var gone = IsAbsent(target);
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
                try
                {
                    await platform.SaveResultAsync(backupDirectory, new(backupDirectory, outcomes.ToArray()));
                }
                catch (Exception ex)
                {
                    protocolError = ex.Message;
                }
            }
            var result = new DeviceRemovalResult(backupDirectory, outcomes) { ProtocolError = protocolError };
            if (storage is not null)
            {
                result = DeviceRemovalDatabaseSync.Apply(plan, result, storage);
            }
            try
            {
                await platform.SaveResultAsync(backupDirectory, result);
            }
            catch (Exception ex)
            {
                result = result with { ProtocolError = ex.Message };
            }
            return result;
        }
        finally
        {
            _operation.Release();
        }
    }

    private string ValidateCurrent(DeviceRemovalItem target, IReadOnlyList<DeviceRemovalNode> inventory)
    {
        if (target.Trace is { } trace)
        {
            if (platform is not IRegistryTracePlatform registry || target.InstanceId != trace.RegistryPath)
            {
                return "Некорректный план удаления записи реестра.";
            }

            var traceReason = DeviceTracePolicy.ProtectionReason(trace, inventory, platform.IsPresent);
            if (traceReason.Length > 0)
            {
                return traceReason;
            }

            var fingerprint = registry.ReadTraceFingerprint(trace.RegistryPath);
            return fingerprint is null || fingerprint == trace.Fingerprint ? "" : "Запись реестра изменилась после предварительной проверки.";
        }
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
    private bool IsAbsent(DeviceRemovalItem target) => target.Trace is { } trace
        ? ((IRegistryTracePlatform)platform).ReadTraceFingerprint(trace.RegistryPath) is null
        : !platform.InstanceExists(target.InstanceId) && !platform.IsPresent(target.InstanceId);
    private static DeviceRemovalItem Protected(UsbDeviceRecord device, string reason) =>
        new(device.DeviceInstanceId, device.DisplayName, false, reason, null, []);
}
