using System.Collections.ObjectModel;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;

namespace Guardian.Desktop.ViewModels;

public sealed class ProtectionViewModel : ObservableObject, IPage
{
    private ProtectionState _state = ProtectionState.Unknown;
    private string _footer = Loc.T("Aucune donnée : le service Guardian ne répond pas.");

    public ProtectionViewModel()
    {
        Loc.LanguageChanged += () =>
        {
            Raise(nameof(Title));
            Raise(nameof(Subtitle));
        };
    }

    public ObservableCollection<EngineRow> Engines { get; } = new();

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

    public string Title => Loc.T("Protection en temps réel");

    public string Subtitle => State switch
    {
        ProtectionState.Healthy => Loc.T("Activée et opérationnelle"),
        ProtectionState.Degraded => Loc.T("Dégradée : au moins un moteur ne répond pas normalement"),
        ProtectionState.OutOfDate => Loc.T("Opérationnelle, définitions à mettre à jour"),
        ProtectionState.Stopped => Loc.T("Arrêtée"),
        _ => Loc.T("État inconnu"),
    };

    public string Footer { get => _footer; private set => Set(ref _footer, value); }

    public void Apply(GuardianSnapshot s)
    {
        State = s.State;
        Engines.Clear();
        foreach (var e in s.Engines)
        {
            Engines.Add(new EngineRow(e.Name, e.State));
        }

        Footer = s.State == ProtectionState.Unknown
            ? Loc.T("Aucune donnée : le service Guardian ne répond pas.")
            : s.Threats.Count == 0
                ? $"{Loc.T("Aucune menace détectée. Dernière vérification :")} {Format(s.LastCheck)}"
                : $"{s.Threats.Count} {Loc.T("menace(s) détectée(s). Dernière vérification :")} {Format(s.LastCheck)}";
    }

    private static string Format(DateTime? d) =>
        d is null ? Loc.T("inconnue") : d.Value.Date == DateTime.Today ? $"{Loc.T("aujourd'hui à")} {d:HH:mm}" : $"{d:dd/MM/yyyy HH:mm}";
}

public sealed record EngineRow(string Name, ProtectionState State)
{
    public string Label => State switch
    {
        ProtectionState.Healthy => Loc.T("Active"),
        ProtectionState.Degraded => Loc.T("Dégradée"),
        ProtectionState.OutOfDate => Loc.T("Obsolète"),
        ProtectionState.Stopped => Loc.T("Arrêtée"),
        _ => Loc.T("Inconnue"),
    };
}
