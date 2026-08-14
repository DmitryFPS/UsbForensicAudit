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

        // Обработчики и журнал ставятся раньше любой тяжёлой работы: до этого
        // сбой на недоступной машине не оставлял в app.log ни одной строки.
        RegisterGlobalExceptionHandlers();

        AppLog.Info("Application startup");
        AppLog.BeginSession();
        AppLog.WriteEnvironment();
        InteractionLog.Attach();

        SessionEnding += (_, args) =>
            AppLog.Info($"Windows завершает сеанс пользователя: {args.ReasonSessionEnding}");

        if (!AdminHelper.IsAdministrator())
        {
            AppLog.Stage("Выход: нет прав администратора");
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

        // Даты показываются в зоне машины аналитика, а не в жёстко зашитой
        // московской: на компьютере в другом часовом поясе фиксированная зона
        // расходилась с настенными часами и путала чтение таймлайна.
        DateDisplay.DisplayZone = TimeZoneInfo.Local;

        // Только запуск опроса: результат нужен при сканировании и в отчётах,
        // а ждать WMI до появления окна нельзя — именно на этом приложение зависало.
        EndpointProtectionEnvironment.BeginProbe();
        AppLog.Stage($"Корпоративная защита USB установлена={EndpointProtectionEnvironment.IsInstalled}, опрос идёт в фоне");

        AppLog.Stage("Сборка контейнера зависимостей");
        _host = Host.CreateDefaultBuilder()
            .ConfigureServices(services =>
            {
                services.AddApplicationServices();
                services.AddInfrastructureServices();
                services.AddSingleton<MainViewModel>();
                services.AddSingleton<MainWindow>();
            })
            .Build();

        AppLog.Stage("Создание главного окна и хранилища");
        var mainWindow = _host.Services.GetRequiredService<MainWindow>();

        AppLog.Stage("Показ главного окна");
        mainWindow.ContentRendered += LogFirstRender;
        DarkWindowChrome.Apply(mainWindow, hideUntilReady: true);
        mainWindow.Show();

        AppLog.Stage("OnStartup завершён, управление передано циклу сообщений");
    }

    private void LogFirstRender(object? sender, EventArgs e)
    {
        if (sender is Window window)
        {
            window.ContentRendered -= LogFirstRender;
        }

        AppLog.Stage("Окно отрисовано, приложение готово к работе");
        InteractionLog.MarkReady();
    }

    private void RegisterGlobalExceptionHandlers()
    {
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
    }

    protected override void OnExit(ExitEventArgs e)
    {
        AppLog.EndSession($"код выхода {e.ApplicationExitCode}");
        _host?.Dispose();
        base.OnExit(e);
    }
}
