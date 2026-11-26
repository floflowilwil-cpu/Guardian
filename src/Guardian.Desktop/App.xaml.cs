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

        // Tant que l'IPC n'est pas branché, le client hors-ligne affiche honnêtement "État inconnu".
        // Lancer avec --demo pour prévisualiser les écrans avec des données fictives.
        IGuardianClient client = e.Args.Contains("--demo")
            ? new DemoGuardianClient()
            : new OfflineGuardianClient();

        var window = new MainWindow { DataContext = new MainViewModel(client) };
        MainWindow = window;
        window.Show();
    }
}
