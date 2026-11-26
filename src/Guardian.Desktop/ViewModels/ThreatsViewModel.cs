using System.Collections.ObjectModel;
using System.Windows.Input;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;
using Guardian.Desktop.Services;

namespace Guardian.Desktop.ViewModels;

public sealed class ThreatsViewModel : ObservableObject, IPage
{
    private readonly IGuardianClient _client;
    private ThreatItem? _selected;
    private int _blocked;
    private int _inQuarantine;
    private int _events;
    private bool _showDetails;
    private string _message = string.Empty;

    public ThreatsViewModel(IGuardianClient client)
    {
        _client = client;
        QuarantineCommand = new RelayCommand(async () => await QuarantineAsync(), () => Selected is not null);
        ToggleDetailsCommand = new RelayCommand(() => ShowDetails = !ShowDetails, () => Selected is not null);
    }

    public ObservableCollection<ThreatItem> Threats { get; } = new();

    public ICommand QuarantineCommand { get; }

    public ICommand ToggleDetailsCommand { get; }

    public ThreatItem? Selected
    {
        get => _selected;
        set
        {
            if (Set(ref _selected, value))
            {
                ShowDetails = false;
                Raise(nameof(RiskText));
            }
        }
    }

    public string RiskText => Selected?.Risk switch
    {
        RiskLevel.High => "Élevé",
        RiskLevel.Medium => "Moyen",
        RiskLevel.Low => "Faible",
        _ => string.Empty,
    };

    public int Blocked { get => _blocked; private set => Set(ref _blocked, value); }

    public int InQuarantine { get => _inQuarantine; private set => Set(ref _inQuarantine, value); }

    public int Events { get => _events; private set => Set(ref _events, value); }

    public bool ShowDetails { get => _showDetails; private set => Set(ref _showDetails, value); }

    public string Message { get => _message; private set => Set(ref _message, value); }

    public void Apply(GuardianSnapshot s)
    {
        var selectedId = Selected?.Id;
        Threats.Clear();
        foreach (var t in s.Threats)
        {
            Threats.Add(t);
        }

        Selected = Threats.FirstOrDefault(t => t.Id == selectedId) ?? Threats.FirstOrDefault();
        Blocked = s.BlockedThreats;
        InQuarantine = s.Quarantine.Count;
        Events = s.EventCount;
    }

    private async Task QuarantineAsync()
    {
        if (Selected is null)
        {
            return;
        }

        var ok = await _client.QuarantineThreatAsync(Selected.Id);
        Message = ok
            ? "Demande de mise en quarantaine envoyée au service."
            : "Le service n'a pas pu traiter la demande.";
    }
}
