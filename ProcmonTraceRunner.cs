namespace UsbForensicAudit;

public static class ProcmonTraceRunner
{
    public static Task<ProcmonTraceResult> TraceAsync(
        ProcmonTraceRequest request,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => TraceOnStaThread(request, progress, cancellationToken), cancellationToken);
    }

    private static ProcmonTraceResult TraceOnStaThread(
        ProcmonTraceRequest request,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ProcmonTraceResult? result = null;
        Exception? error = null;

        var thread = new Thread(() =>
        {
            try
            {
                result = ProcmonTraceService.TraceAsync(request, progress, cancellationToken).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                error = ex;
            }
        })
        {
            IsBackground = true
        };

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        if (error is not null)
        {
            throw error;
        }

        return result!;
    }
}
