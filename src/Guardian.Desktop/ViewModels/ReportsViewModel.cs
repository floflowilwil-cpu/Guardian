using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Input;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;
using Guardian.Desktop.Services;
using Microsoft.Win32;

namespace Guardian.Desktop.ViewModels;

/// <summary>Ligne de l'historique des analyses (libellés calculés à l'affichage, donc suivent la langue).</summary>
public sealed class ScanRecordRow
{
    public ScanRecordRow(ScanRecord record) => Record = record;

    public ScanRecord Record { get; }

    public string DateText => Record.StartedAt.ToString("dd/MM/yyyy HH:mm");

    public string KindLabel => ReportFormat.KindLabel(Record.Kind);

    public string DurationText => ReportFormat.Duration(Record.DurationSeconds);

    public string FilesText => Record.FilesScanned.ToString("N0");

    public int Threats => Record.Threats;

    public string OutcomeLabel => ReportFormat.OutcomeLabel(Record.Outcome);

    public StatusTone Tone => Record.Outcome switch
    {
        ScanOutcome.Failed => StatusTone.Bad,
        ScanOutcome.Cancelled => StatusTone.Warning,
        _ => Record.Threats > 0 ? StatusTone.Bad : StatusTone.Good,
    };

    public StatusTone ThreatsTone => Record.Threats > 0 ? StatusTone.Bad : StatusTone.Neutral;
}

/// <summary>Menace de la dernière analyse, avec son niveau de risque traduit.</summary>
public sealed class ThreatRow
{
    public ThreatRow(ThreatItem threat) => Threat = threat;

    public ThreatItem Threat { get; }

    public string Name => Threat.Name;

    public string Path => Threat.Path;

    public RiskLevel Risk => Threat.Risk;

    public string RiskLabel => ReportFormat.RiskLabel(Threat.Risk);

    public string DateText => Threat.DetectedAt.ToString("dd/MM/yyyy HH:mm");
}

/// <summary>
/// Page "Historique et rapports" : statistiques sur une période, historique des analyses,
/// menaces de la dernière analyse et export du rapport (HTML ou CSV).
/// </summary>
public sealed class ReportsViewModel : ObservableObject, IPage
{
    private readonly ScanHistoryStore _store;
    private GuardianSnapshot _snapshot = GuardianSnapshot.Unknown;
    private int _periodIndex = 1; // 30 jours par défaut
    private int _scansCount;
    private int _filesScanned;
    private int _threatsFound;
    private bool _hasHistory;
    private bool _hasAnyHistory;
    private string _lastScanText = string.Empty;
    private string _message = string.Empty;

    public ReportsViewModel(ScanHistoryStore store, Action requestScan)
    {
        _store = store;
        StartScanCommand = new RelayCommand(requestScan);
        ExportCommand = new RelayCommand(Export);
        ClearCommand = new RelayCommand(Clear, () => _hasAnyHistory);

        _store.Changed += Refresh;
        Loc.LanguageChanged += Refresh;
        Refresh();
    }

    public ObservableCollection<ScanRecordRow> History { get; } = new();

    public ObservableCollection<ThreatRow> Threats { get; } = new();

    public ICommand StartScanCommand { get; }

    public ICommand ExportCommand { get; }

    public ICommand ClearCommand { get; }

    /// <summary>0 = 7 jours, 1 = 30 jours, 2 = tout l'historique.</summary>
    public int PeriodIndex
    {
        get => _periodIndex;
        set
        {
            if (Set(ref _periodIndex, value))
            {
                Refresh();
            }
        }
    }

    public int ScansCount { get => _scansCount; private set => Set(ref _scansCount, value); }

    public int FilesScanned { get => _filesScanned; private set => Set(ref _filesScanned, value); }

    public int ThreatsFound { get => _threatsFound; private set => Set(ref _threatsFound, value); }

    public int InQuarantine => _snapshot.Quarantine.Count;

    public bool HasHistory { get => _hasHistory; private set => Set(ref _hasHistory, value); }

    public bool HasThreats => Threats.Count > 0;

    public string LastScanText { get => _lastScanText; private set => Set(ref _lastScanText, value); }

    public string Message { get => _message; private set => Set(ref _message, value); }

    public void Apply(GuardianSnapshot s)
    {
        _snapshot = s;

        Threats.Clear();
        foreach (var t in s.Threats)
        {
            Threats.Add(new ThreatRow(t));
        }

        Raise(nameof(HasThreats));
        Raise(nameof(InQuarantine));
    }

    private DateTime PeriodStart() => PeriodIndex switch
    {
        0 => DateTime.Now.AddDays(-7),
        1 => DateTime.Now.AddDays(-30),
        _ => DateTime.MinValue,
    };

    private string PeriodLabel() => PeriodIndex switch
    {
        0 => Loc.T("7 derniers jours"),
        1 => Loc.T("30 derniers jours"),
        _ => Loc.T("Tout l'historique"),
    };

    private List<ScanRecord> RecordsInPeriod()
    {
        var since = PeriodStart();
        return _store.Records.Where(r => r.StartedAt >= since).ToList();
    }

    private void Refresh()
    {
        var all = _store.Records;
        var scans = RecordsInPeriod();

        History.Clear();
        foreach (var r in scans)
        {
            History.Add(new ScanRecordRow(r));
        }

        ScansCount = scans.Count;
        FilesScanned = scans.Sum(r => r.FilesScanned);
        ThreatsFound = scans.Sum(r => r.Threats);
        HasHistory = scans.Count > 0;
        _hasAnyHistory = all.Count > 0;

        LastScanText = all.Count > 0
            ? Loc.T("Dernière analyse :") + " " + all[0].StartedAt.ToString("dd/MM/yyyy HH:mm")
            : Loc.T("Aucune analyse enregistrée");

        Raise(nameof(InQuarantine));
        CommandManager.InvalidateRequerySuggested();
    }

    private void Export()
    {
        var dialog = new SaveFileDialog
        {
            Title = Loc.T("Exporter le rapport"),
            FileName = $"guardian-rapport-{DateTime.Now:yyyyMMdd-HHmm}",
            Filter = Loc.T("Rapport HTML") + " (*.html)|*.html|" + Loc.T("Données CSV") + " (*.csv)|*.csv",
            DefaultExt = ".html",
            AddExtension = true,
            OverwritePrompt = true,
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            var scans = RecordsInPeriod();
            var asCsv = string.Equals(Path.GetExtension(dialog.FileName), ".csv", StringComparison.OrdinalIgnoreCase);
            var content = asCsv
                ? ReportExporter.BuildCsv(scans)
                : ReportExporter.BuildHtml(new ReportData(
                    DateTime.Now, PeriodLabel(), _snapshot.State, scans,
                    _snapshot.Threats, _snapshot.Quarantine.Count));

            // BOM UTF-8 : Excel et le Bloc-notes reconnaissent les accents.
            File.WriteAllText(dialog.FileName, content, new UTF8Encoding(true));
            Message = string.Format(Loc.T("Rapport exporté : {0}"), dialog.FileName);
        }
        catch (Exception ex)
        {
            AppLog.Write(ex, "Export du rapport");
            Message = string.Format(Loc.T("L'export a échoué : {0}"), ex.Message);
        }
    }

    private void Clear()
    {
        var answer = MessageBox.Show(
            Loc.T("Effacer tout l'historique des analyses ? Cette action est irréversible."),
            "Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        _store.Clear();
        Message = Loc.T("Historique effacé.");
    }
}
