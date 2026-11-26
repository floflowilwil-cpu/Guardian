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
