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
        SetupApiDeviceRelations.Apply(result.Devices, result.Evidence);
        var inventory = DeviceRemovalSelection.WithHistoricalParents(platform.ReadInventory(), result.Devices.Select(x => new DeviceRemovalNode(
            x.DeviceInstanceId, x.DisplayName, false, ParentDeviceInstanceId: x.ParentDeviceInstanceId)));
        var items = new List<DeviceRemovalItem>();
        var databaseRecords = new List<DeviceRemovalDatabaseRecord>();
        foreach (var record in selected)
        {
            var artifact = DeviceRemovalSelection.IsSharedArtifact(record);
            var sources = DeviceRemovalSelection.Records(record, result, inventory);
            var before = items.Count;
            foreach (var source in sources)
            {
                foreach (var path in DeviceTracePolicy.UnsupportedSourcePaths(source))
                {
                    items.Add(new(path, source.DisplayName, false,
                        "Выборочная очистка этого источника не поддерживается. Запись Windows не удаляется, карточка останется в базе.", null, []));
                }
            }
            if (platform is IRegistryTracePlatform registry)
            {
                foreach (var source in sources)
                {
                    foreach (var path in DeviceTracePolicy.SourcePaths(source))
                    {
                        string? fingerprint;
                        try
                        {
                            if (DeviceTracePolicy.EnumInstanceId(path) is not null && registry.IsActiveEnumPath(path))
                            {
                                continue;
                            }

                            fingerprint = registry.ReadTraceFingerprint(path);
                        }
                        catch (Exception ex) when (ex is UnauthorizedAccessException or System.IO.IOException or System.Security.SecurityException)
                        {
                            items.Add(new(path, source.DisplayName, false, "Не удалось прочитать запись: " + ex.Message, null, []));
                            continue;
                        }
                        if (DeviceTracePolicy.Bind(path, source, fingerprint ?? "") is not { } trace)
                        {
                            items.Add(new(path, source.DisplayName, false,
                                "Не подтверждена принадлежность записи удаляемому USB-устройству или запись относится к инфраструктуре Windows.", null, []));
                            continue;
                        }

                        string reason;
                        try
                        {
                            reason = DeviceTracePolicy.ProtectionReason(trace, inventory, platform.IsPresent);
                            if (reason.Length == 0)
                            {
                                reason = registry.GetTraceProtectionReason(trace);
                            }
                        }
                        catch (Exception ex) when (ex is UnauthorizedAccessException or System.IO.IOException
                            or System.Security.SecurityException or System.ComponentModel.Win32Exception or InvalidOperationException)
                        {
                            reason = "Не удалось проверить состояние записи: " + ex.Message;
                        }
                        var name = source.DisplayName + (trace.Vid.Length > 0 ? " — общий кэш модели" : " — история Windows");
                        items.Add(new(path, name, reason.Length == 0, reason, null, trace.DeviceIds, trace));
                    }
                }
            }
            var matches = DeviceRemovalSelection.Nodes(artifact ? [] : sources.Where(x => !DeviceRemovalSelection.IsSharedArtifact(x)), inventory);
            if (matches.Length == 0)
            {
                if (items.Count == before)
                {
                    items.Add(Protected(record, artifact
                        ? "Общий кэш или сопоставление томов. Выборочная очистка этого источника не поддерживается; одного имени или буквы диска недостаточно для связи с устройством."
                        : "Нет доступной для выборочной очистки записи Windows. Карточка останется в базе."));
                }
            }
            foreach (var node in matches)
            {
                var related = DeviceRemovalPolicy.Related(node, inventory);
                var reason = DeviceRemovalPolicy.ProtectionReason(node, related);
                if (reason.Length == 0 && sources.Any(source => source.DeviceInstanceId.Equals(node.InstanceId, StringComparison.OrdinalIgnoreCase)
                    && SetupApiDeviceRelations.IsStorageUsbParent(source.DeviceInstanceId, source.ParentDeviceInstanceId)
                    && !source.ParentDeviceInstanceId.Equals(node.ParentDeviceInstanceId, StringComparison.OrdinalIgnoreCase)))
                {
                    reason = "USB-родитель устройства изменился со времени сканирования.";
                }
                if (reason.Length == 0 && SetupApiDeviceRelations.IsSupportedParent(node.InstanceId, node.ParentDeviceInstanceId)
                    && platform.IsPresent(node.ParentDeviceInstanceId))
                {
                    reason = "Родительское устройство сейчас подключено.";
                }
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
                .ToArray();
            if (targets.Length == 0)
            {
                throw new InvalidOperationException("В плане нет доступных для удаления экземпляров.");
            }
            var inventory = DeviceRemovalSelection.WithHistoricalParents(platform.ReadInventory(), targets.Where(x => x.Identity is not null).Select(x => x.Identity!));
            // История SCSI и дочерние PnP-узлы подтверждают связь с USB через родителей.
            // Обрабатываем их, пока родитель ещё существует и доступен повторной проверке.
            targets = targets.OrderBy(x => BluetoothCacheIdentity.AddressFromPath(x.Trace?.RegistryPath ?? "").Length > 0 ? 2 : x.Trace is null ? 1 : 0)
                .ThenBy(x => x.Identity is { } node && DeviceRemovalPolicy.HasUsbEvidence(node) ? 1 : 0)
                .ThenBy(x => x.Identity is { } node && BluetoothEnumeratorId.IsClassicPairingTarget(node.InstanceId) ? 1 : 0)
                .ThenByDescending(x => x.Identity is { } node ? ParentDepth(node, inventory, []) : 0).ToArray();
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
                    var currentInventory = platform.ReadInventory();
                    var error = ValidateCurrent(target, currentInventory);
                    if (error.Length == 0 && BluetoothCacheIdentity.AddressFromPath(target.Trace?.RegistryPath ?? "") is { Length: > 0 } address
                        && currentInventory.Any(node => BluetoothEnumeratorId.DeviceAddress(node.InstanceId) == address) && !IsAbsent(target))
                    {
                        error = "Кэш Bluetooth сохранён: остались PnP-компоненты устройства. Сначала завершите их удаление.";
                    }
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
            var result = new DeviceRemovalResult(backupDirectory, outcomes)
            { ProtocolError = protocolError, SkippedCount = plan.ProtectedCount };
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
            if (DeviceTracePolicy.EnumInstanceId(trace.RegistryPath) is not null && registry.IsActiveEnumPath(trace.RegistryPath))
            {
                return "Активные PnP-записи удаляются только штатной командой Windows.";
            }

            var traceReason = DeviceTracePolicy.ProtectionReason(trace, inventory, platform.IsPresent);
            if (traceReason.Length == 0)
            {
                traceReason = registry.GetTraceProtectionReason(trace);
            }
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
        inventory = DeviceRemovalSelection.WithHistoricalParents(inventory, [target.Identity]);
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
        return related.Any(x => platform.IsPresent(x.InstanceId)
            || SetupApiDeviceRelations.IsSupportedParent(x.InstanceId, x.ParentDeviceInstanceId) && platform.IsPresent(x.ParentDeviceInstanceId))
            ? "Устройство или его компонент подключены после проверки." : "";
    }

    private static bool SameIdentity(DeviceRemovalNode a, DeviceRemovalNode b) =>
        a.ContainerId.Equals(b.ContainerId, StringComparison.OrdinalIgnoreCase)
        && a.Service.Equals(b.Service, StringComparison.OrdinalIgnoreCase)
        && a.ClassGuid.Equals(b.ClassGuid, StringComparison.OrdinalIgnoreCase)
        && a.HardwareIds.Equals(b.HardwareIds, StringComparison.OrdinalIgnoreCase)
        && a.ParentIdPrefix.Equals(b.ParentIdPrefix, StringComparison.OrdinalIgnoreCase)
        && a.ParentDeviceInstanceId.Equals(b.ParentDeviceInstanceId, StringComparison.OrdinalIgnoreCase);

    private static int ParentDepth(DeviceRemovalNode node, IReadOnlyList<DeviceRemovalNode> inventory, HashSet<string> ancestors)
    {
        if (!ancestors.Add(node.InstanceId))
        {
            return 0;
        }
        var parents = inventory.Where(other => !other.InstanceId.Equals(node.InstanceId, StringComparison.OrdinalIgnoreCase)
            && !DeviceRemovalPolicy.IsInfrastructure(other)
            // Точный PnP-родитель задаёт порядок и для USBSTOR/WPD/томов.
            // Это не расширяет план удаления и не ослабляет повторную проверку ID.
            && (other.InstanceId.Equals(node.ParentDeviceInstanceId, StringComparison.OrdinalIgnoreCase)
                || DeviceRemovalPolicy.IsChild(other, node))).ToArray();
        var depth = parents.Length == 0 ? 0 : 1 + parents.Max(parent => ParentDepth(parent, inventory, ancestors));
        ancestors.Remove(node.InstanceId);
        return depth;
    }

    private bool IsAbsent(DeviceRemovalItem target) => target.Trace is { } trace
        ? ((IRegistryTracePlatform)platform).ReadTraceFingerprint(trace.RegistryPath) is null
        : !platform.InstanceExists(target.InstanceId) && !platform.IsPresent(target.InstanceId);
    private static DeviceRemovalItem Protected(UsbDeviceRecord device, string reason) =>
        new(device.DeviceInstanceId, device.DisplayName, false, reason, null, []);
}
