using System.Windows.Input;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;

namespace Guardian.Desktop.ViewModels;

public sealed class DashboardViewModel : ObservableObject, IPage
{
    private ProtectionState _state = ProtectionState.Unknown;
    private string _aiText = Loc.T("Inconnu");
    private string _definitionsText = Loc.T("Inconnu");
    private string _realtimeText = Loc.T("Inconnu");
    private string _activity = Loc.T("Aucune donnée : le service Guardian ne répond pas.");

    public DashboardViewModel(Action<ScanKind> requestScan)
    {
        StartScanCommand = new RelayCommand(() => requestScan(ScanKind.Quick));
        StartFullScanCommand = new RelayCommand(() => requestScan(ScanKind.Full));
        Loc.LanguageChanged += () =>
        {
            Raise(nameof(Title));
            Raise(nameof(Subtitle));
        };
    }

    /// <summary>Analyse rapide (zones sensibles), lancée directement.</summary>
    public ICommand StartScanCommand { get; }

    /// <summary>Analyse complète (tous les disques fixes), lancée directement.</summary>
    public ICommand StartFullScanCommand { get; }

    public ProtectionState State
    {
        get => _state;
        private set
        {
            if (Set(ref _state, value))
            {
                Raise(nameof(Title));
                Raise(nameof(Subtitle));
            }
        }
    }

    // L'état "Protégé" n'est affiché que si le service confirme que tout est opérationnel.
    public string Title => State switch
    {
        ProtectionState.Healthy => Loc.T("Protégé"),
        ProtectionState.Degraded => Loc.T("Protection partielle"),
        ProtectionState.OutOfDate => Loc.T("Définitions obsolètes"),
        ProtectionState.Stopped => Loc.T("Protection arrêtée"),
        _ => Loc.T("État inconnu"),
    };

    public string Subtitle => State switch
    {
        ProtectionState.Healthy => Loc.T("Votre appareil est sécurisé"),
        ProtectionState.Degraded => Loc.T("Un ou plusieurs moteurs sont dégradés"),
        ProtectionState.OutOfDate => Loc.T("Mettez à jour les définitions"),
        ProtectionState.Stopped => Loc.T("Le service Guardian est arrêté"),
        _ => Loc.T("En attente du service Guardian"),
    };

    public string AiText { get => _aiText; private set => Set(ref _aiText, value); }

    public string DefinitionsText { get => _definitionsText; private set => Set(ref _definitionsText, value); }

    public string RealtimeText { get => _realtimeText; private set => Set(ref _realtimeText, value); }

    public string Activity { get => _activity; private set => Set(ref _activity, value); }

    public void Apply(GuardianSnapshot s)
    {
        State = s.State;
        var known = s.State != ProtectionState.Unknown;
        AiText = !known ? Loc.T("Inconnu") : s.AiEngineActive ? Loc.T("Actif") : Loc.T("Inactif");
        DefinitionsText = !known ? Loc.T("Inconnu") : s.DefinitionsUpToDate ? Loc.T("À jour") : Loc.T("Obsolètes");
        RealtimeText = !known ? Loc.T("Inconnu") : s.RealtimeActive ? Loc.T("Active") : Loc.T("Inactive");
        Activity = !known
            ? Loc.T("Aucune donnée : le service Guardian ne répond pas.")
            : s.Threats.Count == 0
                ? Loc.T("Aucune menace détectée récemment")
                : $"{s.Threats.Count} {Loc.T("menace(s) détectée(s) récemment")}";
    }
}
