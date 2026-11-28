using System.Windows.Input;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;
using Guardian.Desktop.Services;
using Microsoft.Win32;

namespace Guardian.Desktop.ViewModels;

public sealed class ScanViewModel : ObservableObject, IPage
{
    private readonly IGuardianClient _client;
    private readonly ScanHistoryStore _history;
    private ScanKind _kind = ScanKind.Quick;
    private bool _isScanning;
    private int _percent;
    private string _currentPath = string.Empty;
    private string _message = string.Empty;
    private string? _customPath;
    private int _filesProcessed;
    private int _filesTotal;
    private int _threatsFound;
    private CancellationTokenSource? _cts;

    public ScanViewModel(IGuardianClient client, ScanHistoryStore? history = null)
    {
        _client = client;
        _history = history ?? ScanHistoryStore.Default;
        SelectKindCommand = new RelayCommand(p =>
        {
            if (!IsScanning && p is string s && Enum.TryParse<ScanKind>(s, out var k))
            {
                Kind = k;
            }
        });
        StartCommand = new AsyncRelayCommand(StartAsync, () => !IsScanning);
        Loc.LanguageChanged += () =>
        {
            Raise(nameof(RunningLabel));
            Raise(nameof(Details));
            Raise(nameof(CustomLabel));
        };
        CancelCommand = new RelayCommand(() => _cts?.Cancel(), () => IsScanning);
    }

    public ICommand SelectKindCommand { get; }

    public ICommand StartCommand { get; }

    public ICommand CancelCommand { get; }

    public ScanKind Kind
    {
        get => _kind;
        private set
        {
            if (Set(ref _kind, value))
            {
                Raise(nameof(IsQuick));
                Raise(nameof(IsFull));
                Raise(nameof(IsCustom));
                Raise(nameof(RunningLabel));
            }
        }
    }

    public bool IsQuick => Kind == ScanKind.Quick;

    public bool IsFull => Kind == ScanKind.Full;

    public bool IsCustom => Kind == ScanKind.Custom;

    public bool IsScanning { get => _isScanning; private set => Set(ref _isScanning, value); }

    public int Percent { get => _percent; private set => Set(ref _percent, value); }

    public string CurrentPath { get => _currentPath; private set => Set(ref _currentPath, value); }

    public string Message { get => _message; private set => Set(ref _message, value); }

    public string CustomLabel => _customPath ?? Loc.T("Sélectionnez vos dossiers");

    /// <summary>Titre de la carte de progression : indique clairement le type d'analyse en cours.</summary>
    public string RunningLabel
    {
        get
        {
            var name = Kind switch
            {
                ScanKind.Full => "Analyse complète",
                ScanKind.Custom => "Analyse personnalisée",
                _ => "Analyse rapide",
            };

            return Loc.T(name) + " — " + Loc.T("en cours...");
        }
    }

    /// <summary>Compteurs en direct : fichiers analysés et menaces trouvées.</summary>
    public string Details =>
        Loc.T("Fichiers analysés") + " : " + _filesProcessed.ToString("N0") + " / " + _filesTotal.ToString("N0")
        + "   •   " + Loc.T("Menaces") + " : " + _threatsFound;

    /// <summary>Choisit le type d'analyse (utilisé par l'accueil : Analyse rapide / Analyse complète).</summary>
    public void Prepare(ScanKind kind)
    {
        if (!IsScanning)
        {
            Kind = kind;
        }
    }

    public void Apply(GuardianSnapshot snapshot)
    {
    }

    private async Task StartAsync()
    {
        if (Kind == ScanKind.Custom)
        {
            var dialog = new OpenFolderDialog { Title = "Dossier à analyser" };
            if (dialog.ShowDialog() != true)
            {
                return;
            }

            _customPath = dialog.FolderName;
            Raise(nameof(CustomLabel));
        }

        _cts = new CancellationTokenSource();
        IsScanning = true;
        Percent = 0;
        CurrentPath = string.Empty;
        _filesProcessed = _filesTotal = _threatsFound = 0;
        Raise(nameof(Details));
        Raise(nameof(RunningLabel));
        Message = string.Empty;
        var last = new ScanProgress(0, string.Empty);
        var startedAt = DateTime.Now;
        var clock = System.Diagnostics.Stopwatch.StartNew();
        ScanOutcome? outcome = null; // reste vide si le service n'a pas démarré l'analyse : rien à enregistrer
        try
        {
            var progress = new Progress<ScanProgress>(p =>
            {
                last = p;
                Percent = p.Percent;
                CurrentPath = p.CurrentPath;
                _filesProcessed = p.FilesProcessed;
                _filesTotal = p.FilesTotal;
                _threatsFound = p.ThreatsFound;
                Raise(nameof(Details));
            });

            var accepted = await _client.StartScanAsync(Kind, _customPath, progress, _cts.Token);
            if (accepted)
            {
                outcome = ScanOutcome.Completed;
            }

            Message = accepted
                ? string.Format(
                    Loc.T("Analyse terminée : {0} fichier(s) analysé(s), {1} ignoré(s), {2} menace(s)."),
                    Math.Max(0, last.FilesProcessed - last.FilesSkipped), last.FilesSkipped, last.ThreatsFound)
                : Loc.T("Impossible de lancer l'analyse : le service Guardian ne répond pas.");
        }
        catch (OperationCanceledException)
        {
            outcome = ScanOutcome.Cancelled;
            Message = Loc.T("Analyse annulée.");
        }
        catch (Exception ex)
        {
            outcome = ScanOutcome.Failed;
            AppLog.Write(ex, "Analyse");
            Message = string.Format(Loc.T("L'analyse a échoué : {0}"), ex.Message);
        }
        finally
        {
            IsScanning = false;
            _cts?.Dispose();
            _cts = null;

            if (outcome is { } result)
            {
                // Alimente l'écran Historique et rapports.
                _history.Add(new ScanRecord(
                    Guid.NewGuid(), startedAt, Kind, clock.Elapsed.TotalSeconds,
                    Math.Max(0, last.FilesProcessed - last.FilesSkipped), last.FilesSkipped,
                    last.ThreatsFound, result));
            }
        }
    }
}
