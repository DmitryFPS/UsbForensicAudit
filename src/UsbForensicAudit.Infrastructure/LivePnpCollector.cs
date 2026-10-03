namespace UsbForensicAudit;

internal static class LivePnpCollector
{
    internal static List<UsbDeviceRecord> Collect(WindowsPnpSnapshot snapshot, DateTimeOffset observedAt)
    {
        var records = new List<UsbDeviceRecord>();
        foreach (var (id, state) in snapshot.States)
        {
            var metadata = LiveDeviceMetadataReader.Read(id);
            var identity = LiveDeviceMetadataReader.ReadIdentity(id);
            if (!DeviceTransportClassifier.IsRelevantLiveCandidate(id, metadata.Service, metadata.HardwareIds,
                    metadata.CompatibleIds, metadata.LocationPaths, metadata.Product)
                && !DeviceTransportClassifier.IsBuiltinStorageLiveCandidate(id, metadata.Service, metadata.HardwareIds,
                    metadata.CompatibleIds, metadata.LocationPaths, metadata.Product)
                && !SetupApiDeviceRelations.IsStorageUsbParent(id, identity.Parent))
            { continue; }

            var codes = LiveDeviceIdentity.ExtractVidPid(id);
            var record = new UsbDeviceRecord
            {
                DeviceInstanceId = id, Source = "Live: Windows PnP", DeviceType = id.Split('\\')[0],
                VisualCategory = "RealUsb", FriendlyName = identity.Name, Product = metadata.Product,
                Manufacturer = metadata.Manufacturer, Revision = metadata.Revision, Service = metadata.Service,
                HardwareIds = metadata.HardwareIds, CompatibleIds = metadata.CompatibleIds,
                LocationPaths = metadata.LocationPaths, LocationInformation = metadata.LocationInformation,
                ParentDeviceInstanceId = identity.Parent, ContainerId = identity.Container, ClassGuid = identity.ClassGuid,
                Vid = codes.Vid, Pid = codes.Pid, Serial = LiveDeviceIdentity.ExtractSerial(id),
                IsCurrentlyConnected = state == true,
                CurrentConnectionState = state switch { true => "Connected", false => "Disconnected", _ => "Unknown" },
                CollectedAtUtc = observedAt,
                UserMeaning = "Запись устройства Windows; состояние соединения проверяется отдельно от регистрации PnP."
            };
            if (state == true)
            {
                record.FirstConnectedUtc = record.LastSeenUtc = observedAt;
                record.ConnectionDisplayKind = "LiveAtScan";
                record.DisconnectDisplayKind = "ConnectedNow";
                record.FirstConnectedProvenance = record.LastSeenProvenance = $"Текущее присутствие/соединение Windows, опрос {observedAt:O}";
                record.DateConfidence = "Устройство подключено в момент опроса; это не время начала подключения.";
            }
            else if (!state.HasValue)
            {
                record.DisconnectDisplayKind = "ConnectionUnknown";
                record.DateConfidence = "Устройство зарегистрировано в PnP; радиосоединение Bluetooth не удалось проверить.";
            }
            DeviceTransportClassifier.Classify(record);
            if (state == true && record.Connection == "USB")
            {
                var connector = UsbConnectorProbe.Read(id);
                record.ConnectorType = connector.Type;
                record.ConnectorProvenance = connector.Provenance;
            }
            records.Add(record);
        }
        return records;
    }
}
