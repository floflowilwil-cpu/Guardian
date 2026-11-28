using System.Collections.ObjectModel;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;

namespace Guardian.Desktop.ViewModels;

/// <summary>
/// Page "Surveillance système" : posture de sécurité de Windows (Defender, pare-feu, UAC...),
/// recommandations et événements récents. Lecture seule : Guardian n'y modifie jamais Windows.
/// </summary>
public sealed class SystemViewModel : ObservableObject, IPage
{
    private const int MaxEvents = 25;

    private bool _hasData;
    private ProtectionState _state = ProtectionState.Unknown;
    private string _headline = string.Empty;
    private string _osText = string.Empty;
    private string _privilegeText = string.Empty;
    private string _capturedText = string.Empty;
    private int _activeCount;
    private int _totalCount;

    public SystemViewModel()
    {
        Apply(GuardianSnapshot.Unknown);
    }

    public ObservableCollection<SecurityControlRow> Controls { get; } = new();

    public ObservableCollection<string> Recommendations { get; } = new();

    public ObservableCollection<SystemEventRow> Events { get; } = new();

    /// <summary>Faux tant que le service n'a fourni aucune donnée système.</summary>
    public bool HasData { get => _hasData; private set => Set(ref _hasData, value); }

    public bool HasRecommendations => Recommendations.Count > 0;

    public bool HasEvents => Events.Count > 0;

    public ProtectionState State { get => _state; private set => Set(ref _state, value); }

    public string Headline { get => _headline; private set => Set(ref _headline, value); }

    public string OsText { get => _osText; private set => Set(ref _osText, value); }

    public string PrivilegeText { get => _privilegeText; private set => Set(ref _privilegeText, value); }

    public string CapturedText { get => _capturedText; private set => Set(ref _capturedText, value); }

    /// <summary>Nombre de protections actives, sur le total observé (ex. "6 / 8").</summary>
    public string ScoreText => $"{_activeCount} / {_totalCount}";

    public void Apply(GuardianSnapshot s)
    {
        var info = s.SystemInfo;

        Controls.Clear();
        Recommendations.Clear();
        Events.Clear();

        if (info is null)
        {
            HasData = false;
            State = ProtectionState.Unknown;
            Headline = Loc.T("Aucune donnée système");
            OsText = Loc.T("Le service Guardian ne répond pas : l'état de Windows est inconnu.");
            PrivilegeText = string.Empty;
            CapturedText = string.Empty;
            _activeCount = _totalCount = 0;
            Raise(nameof(ScoreText));
            Raise(nameof(HasRecommendations));
            Raise(nameof(HasEvents));
            return;
        }

        foreach (var c in info.Controls)
        {
            Controls.Add(c);
        }

        foreach (var r in info.Recommendations.Where(r => !string.IsNullOrWhiteSpace(r)))
        {
            Recommendations.Add(r);
        }

        foreach (var e in info.Events.OrderByDescending(e => e.Time).Take(MaxEvents))
        {
            Events.Add(e);
        }

        _activeCount = info.Controls.Count(c => c.State == ProtectionState.Healthy);
        _totalCount = info.Controls.Count;
        var inactive = info.Controls.Count(c => c.State == ProtectionState.Stopped);
        var unknown = info.Controls.Count(c => c.State == ProtectionState.Unknown);

        // "Protégé" n'est jamais affiché par défaut : tout contrôle inactif ou non vérifié est signalé.
        if (_totalCount == 0)
        {
            State = ProtectionState.Unknown;
            Headline = Loc.T("Aucune protection Windows observée");
        }
        else if (inactive > 0)
        {
            State = ProtectionState.Degraded;
            Headline = string.Format(Loc.T("{0} protection(s) Windows inactive(s)"), inactive);
        }
        else if (unknown > 0)
        {
            State = ProtectionState.Unknown;
            Headline = Loc.T("Certaines protections n'ont pas pu être vérifiées");
        }
        else
        {
            State = ProtectionState.Healthy;
            Headline = Loc.T("Les protections Windows sont actives");
        }

        HasData = true;
        OsText = string.Join("  •  ", new[] { info.WindowsEdition, info.OsVersion }.Where(x => !string.IsNullOrWhiteSpace(x)));
        if (OsText.Length == 0)
        {
            OsText = Loc.T("Version de Windows inconnue");
        }

        PrivilegeText = Loc.T("Droits de Guardian :") + " " + info.Privilege switch
        {
            PrivilegeKind.Standard => Loc.T("utilisateur standard"),
            PrivilegeKind.Administrator => Loc.T("administrateur"),
            PrivilegeKind.System => Loc.T("système"),
            _ => Loc.T("inconnus"),
        };

        CapturedText = info.CapturedAt is { } at
            ? Loc.T("Dernière lecture :") + " " + at.ToString("HH:mm:ss")
            : string.Empty;

        Raise(nameof(ScoreText));
        Raise(nameof(HasRecommendations));
        Raise(nameof(HasEvents));
    }
}
