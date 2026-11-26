using System.Collections.ObjectModel;
using System.Windows.Input;
using System.Windows.Threading;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;
using Guardian.Desktop.Services;

namespace Guardian.Desktop.ViewModels;

public sealed class NavItem : ObservableObject
{
    private bool _isSelected;

    public NavItem(string title, string glyph, IPage page)
    {
        Title = title;
        Glyph = glyph;
        Page = page;
    }

    public string Title { get; }

    public string Glyph { get; }

    public IPage Page { get; }

    public bool IsSelected { get => _isSelected; set => Set(ref _isSelected, value); }
}

public sealed class MainViewModel : ObservableObject
{
    private readonly IGuardianClient _client;
    private readonly DispatcherTimer _timer;
    private NavItem _selected;
    private bool _refreshing;

    public MainViewModel(IGuardianClient client)
    {
        _client = client;

        ScanPage = new ScanViewModel(client);
        var dashboard = new DashboardViewModel(() => Navigate(ScanPage));

        Items =
        [
            new("Accueil", "", dashboard),
            new("Analyse", "", ScanPage),
            new("Protection", "", new ProtectionViewModel()),
            new("Menaces", "", new ThreatsViewModel(client)),
            new("Quarantaine", "", new QuarantineViewModel(client)),
            new("Réseau", "", new NetworkViewModel()),
            new("Système", "", new PlaceholderViewModel("Surveillance système")),
            new("Rapports", "", new PlaceholderViewModel("Historique et rapports")),
            new("IA Assistant", "", new AssistantViewModel(client)),
            new("Paramètres", "", new SettingsViewModel()),
        ];

        NavigateCommand = new RelayCommand(p =>
        {
            if (p is NavItem item)
            {
                Select(item);
            }
        });

        _selected = Items[0];
        _selected.IsSelected = true;

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _timer.Tick += async (_, _) =>
        {
            try { await RefreshAsync(); }
            catch (Exception ex) { AppLog.Write(ex, "Actualisation périodique"); }
        };
        _timer.Start();
        _ = RefreshAsync();
    }

    public ObservableCollection<NavItem> Items { get; }

    public ScanViewModel ScanPage { get; }

    public ICommand NavigateCommand { get; }

    public bool IsDemo => _client.IsDemo;

    public NavItem Selected
    {
        get => _selected;
        private set
        {
            if (Set(ref _selected, value))
            {
                Raise(nameof(CurrentPage));
            }
        }
    }

    public IPage CurrentPage => Selected.Page;

    private void Navigate(IPage page)
    {
        var item = Items.FirstOrDefault(i => ReferenceEquals(i.Page, page));
        if (item is not null)
        {
            Select(item);
        }
    }

    private void Select(NavItem item)
    {
        Selected.IsSelected = false;
        item.IsSelected = true;
        Selected = item;
    }

    private async Task RefreshAsync()
    {
        if (_refreshing)
        {
            return;
        }

        _refreshing = true;
        try
        {
            GuardianSnapshot snapshot;
            try
            {
                snapshot = await _client.GetSnapshotAsync();
            }
            catch
            {
                // Service injoignable : on ne simule jamais une protection active.
                snapshot = GuardianSnapshot.Unknown;
            }

            foreach (var item in Items)
            {
                try { item.Page.Apply(snapshot); }
                catch (Exception ex) { AppLog.Write(ex, $"Mise à jour de la page {item.Title}"); }
            }
        }
        catch (Exception ex)
        {
            AppLog.Write(ex, "Actualisation des données Guardian");
        }
        finally
        {
            _refreshing = false;
        }
    }
}
