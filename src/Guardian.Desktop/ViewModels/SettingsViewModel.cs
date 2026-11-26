using System.Collections.ObjectModel;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;

namespace Guardian.Desktop.ViewModels;

public sealed class SettingsViewModel : ObservableObject, IPage
{
    private int _themeIndex;
    private string _language = "Français";
    private bool _silentMode;
    private bool _offlineMode;
    private string _enginesSummary = "État des moteurs inconnu";
    private ProtectionState _enginesState = ProtectionState.Unknown;

    public SettingsViewModel()
    {
        var prefs = UiPreferences.Load();
        _themeIndex = (int)prefs.Theme;
        _language = prefs.Language;
        _silentMode = prefs.SilentMode;
        _offlineMode = prefs.OfflineMode;
    }

    public IReadOnlyList<string> Languages { get; } = ["Français", "English"];

    public ObservableCollection<EngineRow> Engines { get; } = new();

    // 0 = Clair, 1 = Sombre, 2 = Automatique
    public int ThemeIndex
    {
        get => _themeIndex;
        set
        {
            if (Set(ref _themeIndex, value))
            {
                ThemeService.Apply((ThemeMode)value);
                Save();
            }
        }
    }

    public string Language
    {
        get => _language;
        set
        {
            if (Set(ref _language, value))
            {
                Save();
            }
        }
    }

    // Le mode silencieux réduit les notifications sans désactiver les protections (doc §9).
    public bool SilentMode
    {
        get => _silentMode;
        set
        {
            if (Set(ref _silentMode, value))
            {
                Save();
            }
        }
    }

    public bool OfflineMode
    {
        get => _offlineMode;
        set
        {
            if (Set(ref _offlineMode, value))
            {
                Save();
            }
        }
    }

    public string EnginesSummary { get => _enginesSummary; private set => Set(ref _enginesSummary, value); }

    public ProtectionState EnginesState { get => _enginesState; private set => Set(ref _enginesState, value); }

    public void Apply(GuardianSnapshot s)
    {
        Engines.Clear();
        foreach (var e in s.Engines)
        {
            Engines.Add(new EngineRow(e.Name, e.State));
        }

        EnginesState = s.State;
        EnginesSummary = s.State switch
        {
            ProtectionState.Healthy => "Tous les moteurs sont opérationnels",
            ProtectionState.Degraded => "Certains moteurs sont dégradés",
            ProtectionState.OutOfDate => "Des définitions sont obsolètes",
            ProtectionState.Stopped => "Le service Guardian est arrêté",
            _ => "État des moteurs inconnu",
        };
    }

    private void Save() =>
        UiPreferences.Save(new UiPreferences((ThemeMode)ThemeIndex, Language, SilentMode, OfflineMode));
}
