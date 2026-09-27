namespace UsbForensicAudit;

public static class DeviceRemovalDatabaseSync
{
    /// <summary>Удаляем карточку только после успешной обработки всех её целей из подтверждённого плана.</summary>
    public static IReadOnlyList<string> CompletedRecords(DeviceRemovalPlan plan, DeviceRemovalResult result)
    {
        var allowed = plan.Items.GroupBy(x => x.InstanceId, StringComparer.OrdinalIgnoreCase)
            .Where(x => x.All(item => item.CanRemove)).Select(x => x.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var successful = result.Items.GroupBy(x => x.InstanceId, StringComparer.OrdinalIgnoreCase)
            .Where(x => x.All(item => item.Status is "Removed" or "AlreadyAbsent"))
            .Select(x => x.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return plan.DatabaseRecords.GroupBy(x => x.DeviceInstanceId, StringComparer.OrdinalIgnoreCase)
            .Where(group => !string.IsNullOrWhiteSpace(group.Key) && group.All(record => record.TargetIds.Count > 0
                && record.TargetIds.All(id => allowed.Contains(id) && successful.Contains(id))))
            .Select(x => x.Key).ToArray();
    }

    public static DeviceRemovalResult Apply(DeviceRemovalPlan plan, DeviceRemovalResult result, IAuditStorage storage)
    {
        var records = CompletedRecords(plan, result);
        try
        {
            return result with
            {
                DatabaseRemoval = records.Count == 0 ? new(0, "") : storage.DeleteDeviceRecords(plan.SessionId, records)
            };
        }
        catch (Exception ex)
        {
            // Windows уже изменена: ошибку SQLite нельзя выдавать за неудачу команды Windows.
            return result with { DatabaseError = ex.Message };
        }
    }
}
