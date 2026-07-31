namespace UsbForensicAudit;

/// <summary>
/// Снимок обстановки вокруг машины: какие сети Wi-Fi слышны и какие устройства
/// видны в той же сети. Это состояние «сейчас», а не история подключений.
/// </summary>
public interface INetworkEnvironmentService
{
    /// <param name="activeProbe">
    /// Если true, программа сама опрашивает адреса подсети. Это медленнее, но
    /// находит устройства, с которыми машина ещё не разговаривала.
    /// </param>
    Task<NetworkEnvironmentSnapshot> CaptureAsync(
        bool activeProbe,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);
}
