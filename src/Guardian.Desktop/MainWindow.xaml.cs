using System.Windows;

namespace Guardian.Desktop;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        StateChanged += (_, _) => UpdateWindowState();
        UpdateWindowState();
    }

    private void UpdateWindowState()
    {
        // En plein écran, une fenêtre WindowChrome dépasse de l'écran de la largeur de la bordure de redimensionnement :
        // on compense pour que la barre de titre et les boutons restent visibles.
        if (WindowState == WindowState.Maximized)
        {
            BorderThickness = SystemParameters.WindowResizeBorderThickness;
            MaxRestoreButton.Content = "\uE923"; // restaurer
            MaxRestoreButton.ToolTip = "Restaurer";
        }
        else
        {
            BorderThickness = new Thickness(0);
            MaxRestoreButton.Content = "\uE922"; // agrandir
            MaxRestoreButton.ToolTip = "Agrandir";
        }
    }

    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximizeRestore(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
