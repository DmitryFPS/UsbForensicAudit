namespace UsbForensicAudit;

internal static class ExternalUtilityCaptureRunner
{
    private static readonly TimeSpan CaptureTimeout = TimeSpan.FromSeconds(45);

    public static Task<ExternalUtilityCapture> CaptureAsync(
        RunningExternalUtility utility,
        CancellationToken cancellationToken = default)
    {
        return StaTaskRunner.RunAsync(
            () => ExternalUtilityWindowCaptureService.Capture(utility),
            CaptureTimeout,
            cancellationToken);
    }
}
