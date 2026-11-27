using System.Windows;
using Guardian.Desktop.Infrastructure;

namespace Guardian.Desktop;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        FitToWorkArea();
        StateChanged += (_, _) => UpdateWindowState();
        SizeChanged += (_, _) => UpdateBannerSize();
        Loc.LanguageChanged += UpdateWindowState;
        UpdateWindowState();
    }

    /// <summary>
    /// Garantit que la fenêtre tient dans la zone utile de l'écran (hors barre des tâches) :
    /// la barre de titre avec − ☐ ✕ est ainsi toujours visible dès le démarrage, même sur un petit portable.
    /// </summary>
    private void FitToWorkArea()
    {
        var area = SystemParameters.WorkArea;
        const double margin = 12;

        MinWidth = Math.Min(MinWidth, area.Width - margin);
        MinHeight = Math.Min(MinHeight, area.Height - margin);
        Width = Math.Min(Width, area.Width - margin);
        Height = Math.Min(Height, area.Height - margin);

        WindowStartupLocation = WindowStartupLocation.Manual;
        Left = area.Left + ((area.Width - Width) / 2);
        Top = area.Top + ((area.Height - Height) / 2);
    }

    /// <summary>Sur un écran peu haut, le bandeau Guardian se compacte pour laisser la place au contenu.</summary>
    private void UpdateBannerSize()
    {
        var compact = ActualHeight < 720;
        BannerRow.Height = new GridLength(compact ? 90 : 112);
        BannerBorder.Padding = compact ? new Thickness(26, 4, 26, 4) : new Thickness(26, 10, 26, 10);
        BannerShield.Height = compact ? 68 : 88;
    }

    private void UpdateWindowState()
    {
        // En plein écran, une fenêtre WindowChrome dépasse de l'écran de la largeur de la bordure de redimensionnement :
        // on compense pour que la barre de titre et les boutons restent visibles.
        if (WindowState == WindowState.Maximized)
        {
            BorderThickness = SystemParameters.WindowResizeBorderThickness;
            MaxRestoreButton.Content = "\uE923"; // restaurer
            MaxRestoreButton.ToolTip = Loc.T("Restaurer");
        }
        else
        {
            BorderThickness = new Thickness(0);
            MaxRestoreButton.Content = "\uE922"; // agrandir
            MaxRestoreButton.ToolTip = Loc.T("Agrandir");
        }
    }

    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximizeRestore(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
