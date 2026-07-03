using System.Text;
using System.Windows;

namespace UsbForensicAudit;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        EndpointProtectionState.IsProtectionActive = EndpointProtectionEnvironment.IsProtectionActive;

        DispatcherUnhandledException += (_, args) =>
        {
            AppLog.Error(args.Exception, "Unhandled UI exception");
            MessageBox.Show(args.Exception.Message, "UsbForensicAudit error", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception exception)
            {
                AppLog.Error(exception, "Unhandled domain exception");
            }
        };

        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            AppLog.Error(args.Exception, "Unobserved task exception");
            args.SetObserved();
        };

        AppLog.Info("Application startup");
        base.OnStartup(e);

        var mainWindow = new MainWindow();
        DarkWindowChrome.Apply(mainWindow, hideUntilReady: true);
        mainWindow.Show();
    }
}
