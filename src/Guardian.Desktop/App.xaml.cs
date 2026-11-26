using System.Windows;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Services;
using Guardian.Desktop.ViewModels;

namespace Guardian.Desktop;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += (_, args) =>
        {
            AppLog.Write(args.Exception, "Exception UI non interceptée");
            args.Handled = true;
            MessageBox.Show("Une erreur a été interceptée. Guardian reste ouvert. Consultez le journal dans %LOCALAPPDATA%\\Guardian\\guardian-errors.log.",
                "Guardian - erreur", MessageBoxButton.OK, MessageBoxImage.Warning);
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex) AppLog.Write(ex, "Exception fatale");
        };
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            AppLog.Write(args.Exception, "Tâche asynchrone non observée");
            args.SetObserved();
        };

        ThemeService.Apply(UiPreferences.Load().Theme);

        // Le service Guardian (IPC) n'est pas encore branché : l'interface s'ouvre directement
        // avec des données d'exemple, sans argument de lancement nécessaire.
        IGuardianClient client = new DemoGuardianClient();

        var window = new MainWindow { DataContext = new MainViewModel(client) };
        MainWindow = window;
        window.Show();
    }
}
