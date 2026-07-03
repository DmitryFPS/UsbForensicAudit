namespace UsbForensicAudit;

internal static class ExternalUtilityCaptureRunner
{
    public static Task<ExternalUtilityCapture> CaptureAsync(RunningExternalUtility utility)
    {
        return Task.Run(() => CaptureOnStaThread(utility));
    }

    private static ExternalUtilityCapture CaptureOnStaThread(RunningExternalUtility utility)
    {
        ExternalUtilityCapture? result = null;
        Exception? error = null;
        var thread = new Thread(() =>
        {
            try
            {
                result = ExternalUtilityWindowCaptureService.Capture(utility);
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
