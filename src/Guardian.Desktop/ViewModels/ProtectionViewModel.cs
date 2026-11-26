using System.Collections.ObjectModel;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;

namespace Guardian.Desktop.ViewModels;

public sealed class ProtectionViewModel : ObservableObject, IPage
{
    private ProtectionState _state = ProtectionState.Unknown;
    private string _footer = "Aucune donnée : le service Guardian ne répond pas.";

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

    public string Title => "Protection en temps réel";

    public string Subtitle => State switch
    {
        ProtectionState.Healthy => "Activée et opérationnelle",
        ProtectionState.Degraded => "Dégradée : au moins un moteur ne répond pas normalement",
        ProtectionState.OutOfDate => "Opérationnelle, définitions à mettre à jour",
        ProtectionState.Stopped => "Arrêtée",
        _ => "État inconnu",
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
            ? "Aucune donnée : le service Guardian ne répond pas."
            : s.Threats.Count == 0
                ? $"Aucune menace détectée. Dernière vérification : {Format(s.LastCheck)}"
                : $"{s.Threats.Count} menace(s) détectée(s). Dernière vérification : {Format(s.LastCheck)}";
    }

    private static string Format(DateTime? d) =>
        d is null ? "inconnue" : d.Value.Date == DateTime.Today ? $"aujourd'hui à {d:HH:mm}" : $"{d:dd/MM/yyyy HH:mm}";
}

public sealed record EngineRow(string Name, ProtectionState State)
{
    public string Label => State switch
    {
        ProtectionState.Healthy => "Active",
        ProtectionState.Degraded => "Dégradée",
        ProtectionState.OutOfDate => "Obsolète",
        ProtectionState.Stopped => "Arrêtée",
        _ => "Inconnue",
    };
}
