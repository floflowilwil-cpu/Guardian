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

    private readonly string _titleKey;

    public NavItem(string title, string glyph, string iconColor, IPage page)
    {
        _titleKey = title;
        Loc.LanguageChanged += () => Raise(nameof(Title));
        Glyph = glyph;
        IconColor = iconColor;
        Page = page;
    }

    public string Title => Loc.T(_titleKey);

    public string Glyph { get; }

    /// <summary>Couleur de l'icône de l'onglet (ex. "#38BDF8").</summary>
    public string IconColor { get; }

    public IPage Page { get; }

    public bool IsSelected { get => _isSelected; set => Set(ref _isSelected, value); }
}

public sealed class MainViewModel : ObservableObject
{
    private readonly IGuardianClient _client;
    private readonly DispatcherTimer _timer;
    private NavItem _selected;
    private bool _refreshing;
    private GuardianSnapshot _lastSnapshot = GuardianSnapshot.Unknown;

    public MainViewModel(IGuardianClient client)
    {
        _client = client;

        ScanPage = new ScanViewModel(client);
        var dashboard = new DashboardViewModel(kind =>
        {
            // L'accueil lance directement le type d'analyse choisi et ouvre l'écran de progression.
            ScanPage.Prepare(kind);
            Navigate(ScanPage);
            if (ScanPage.StartCommand.CanExecute(null))
            {
                ScanPage.StartCommand.Execute(null);
            }
        });

        Items =
        [
            new("Accueil", "\uE80F", "#38BDF8", dashboard),
            new("Analyse", "\uE721", "#A78BFA", ScanPage),
            new("Protection", "\uEA18", "#34D399", new ProtectionViewModel()),
            new("Menaces", "\uE7BA", "#FBBF24", new ThreatsViewModel(client)),
            new("Quarantaine", "\uE72E", "#FB923C", new QuarantineViewModel(client)),
            new("Réseau", "\uE774", "#22D3EE", new NetworkViewModel()),
            new("Système", "\uE770", "#60A5FA", new SystemViewModel()),
            new("Rapports", "\uE9D9", "#F472B6", new ReportsViewModel(ScanHistoryStore.Default, () => Navigate(ScanPage))),
            new("IA Assistant", "\uE8BD", "#C084FC", new AssistantViewModel(client)),
            new("Paramètres", "\uE713", "#38BDF8", new SettingsViewModel()),
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
        Loc.LanguageChanged += () => ApplyToPages(_lastSnapshot);
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

    private void ApplyToPages(GuardianSnapshot snapshot)
    {
        foreach (var item in Items)
        {
            try { item.Page.Apply(snapshot); }
            catch (Exception ex) { AppLog.Write(ex, $"Mise à jour de la page {item.Title}"); }
        }
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

            _lastSnapshot = snapshot;
            ApplyToPages(snapshot);
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
