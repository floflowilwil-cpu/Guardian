using System.Windows.Input;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;

namespace Guardian.Desktop.ViewModels;

public sealed class DashboardViewModel : ObservableObject, IPage
{
    private ProtectionState _state = ProtectionState.Unknown;
    private string _aiText = "Inconnu";
    private string _definitionsText = "Inconnu";
    private string _realtimeText = "Inconnu";
    private string _activity = "Aucune donnée : le service Guardian ne répond pas.";

    public DashboardViewModel(Action requestScan)
    {
        StartScanCommand = new RelayCommand(requestScan);
    }

    public ICommand StartScanCommand { get; }

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
        ProtectionState.Healthy => "Protégé",
        ProtectionState.Degraded => "Protection partielle",
        ProtectionState.OutOfDate => "Définitions obsolètes",
        ProtectionState.Stopped => "Protection arrêtée",
        _ => "État inconnu",
    };

    public string Subtitle => State switch
    {
        ProtectionState.Healthy => "Votre appareil est sécurisé",
        ProtectionState.Degraded => "Un ou plusieurs moteurs sont dégradés",
        ProtectionState.OutOfDate => "Mettez à jour les définitions",
        ProtectionState.Stopped => "Le service Guardian est arrêté",
        _ => "En attente du service Guardian",
    };

    public string AiText { get => _aiText; private set => Set(ref _aiText, value); }

    public string DefinitionsText { get => _definitionsText; private set => Set(ref _definitionsText, value); }

    public string RealtimeText { get => _realtimeText; private set => Set(ref _realtimeText, value); }

    public string Activity { get => _activity; private set => Set(ref _activity, value); }

    public void Apply(GuardianSnapshot s)
    {
        State = s.State;
        var known = s.State != ProtectionState.Unknown;
        AiText = !known ? "Inconnu" : s.AiEngineActive ? "Actif" : "Inactif";
        DefinitionsText = !known ? "Inconnu" : s.DefinitionsUpToDate ? "À jour" : "Obsolètes";
        RealtimeText = !known ? "Inconnu" : s.RealtimeActive ? "Active" : "Inactive";
        Activity = !known
            ? "Aucune donnée : le service Guardian ne répond pas."
            : s.Threats.Count == 0
                ? "Aucune menace détectée récemment"
                : $"{s.Threats.Count} menace(s) détectée(s) récemment";
    }
}
