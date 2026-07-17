using System.Text;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace UsbForensicAudit;

public partial class App : Application
{
    private IHost? _host;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (!AdminHelper.IsAdministrator())
        {
            MessageBox.Show(
                "Данное приложение можно открыть только с правами администратора.\n\n" +
                "Закройте это сообщение и запустите программу от имени администратора.",
                "Требуются права администратора",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            Shutdown(-1);
            return;
        }

        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        EndpointProtectionState.IsProtectionActive = EndpointProtectionEnvironment.IsProtectionActive;

        DispatcherUnhandledException += (_, args) =>
        {
            AppLog.Error(args.Exception, "Unhandled UI exception");
            MessageBox.Show(
                "Произошла непредвиденная ошибка. Подробности записаны в технический журнал приложения.",
                "UsbForensicAudit error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
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

        _host = Host.CreateDefaultBuilder()
            .ConfigureServices(services =>
            {
                services.AddApplicationServices();
                services.AddInfrastructureServices();
                services.AddSingleton<MainViewModel>();
                services.AddSingleton<MainWindow>();
            })
            .Build();

        var mainWindow = _host.Services.GetRequiredService<MainWindow>();
        DarkWindowChrome.Apply(mainWindow, hideUntilReady: true);
        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _host?.Dispose();
        base.OnExit(e);
    }
}
