namespace UsbForensicAudit;

public static class ProcmonTraceRunner
{
    public static Task<ProcmonTraceResult> TraceAsync(
        ProcmonTraceRequest request,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var timeout = request.CaptureDuration + TimeSpan.FromMinutes(3);
        return StaTaskRunner.RunAsync(
            () => ProcmonTraceService.TraceAsync(request, progress, cancellationToken).GetAwaiter().GetResult(),
            timeout,
            cancellationToken);
    }
}
