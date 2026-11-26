using System.Windows.Input;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;
using Guardian.Desktop.Services;
using Microsoft.Win32;

namespace Guardian.Desktop.ViewModels;

public sealed class ScanViewModel : ObservableObject, IPage
{
    private readonly IGuardianClient _client;
    private ScanKind _kind = ScanKind.Quick;
    private bool _isScanning;
    private int _percent;
    private string _currentPath = string.Empty;
    private string _message = string.Empty;
    private string? _customPath;
    private CancellationTokenSource? _cts;

    public ScanViewModel(IGuardianClient client)
    {
        _client = client;
        SelectKindCommand = new RelayCommand(p =>
        {
            if (!IsScanning && p is string s && Enum.TryParse<ScanKind>(s, out var k))
            {
                Kind = k;
            }
        });
        StartCommand = new RelayCommand(async () => await StartAsync(), () => !IsScanning);
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

    public string CustomLabel => _customPath ?? "Sélectionnez vos dossiers";

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
        Message = string.Empty;
        try
        {
            var progress = new Progress<ScanProgress>(p =>
            {
                Percent = p.Percent;
                CurrentPath = p.CurrentPath;
            });

            var accepted = await _client.StartScanAsync(Kind, _customPath, progress, _cts.Token);
            Message = accepted
                ? "Analyse terminée."
                : "Impossible de lancer l'analyse : le service Guardian ne répond pas.";
        }
        catch (OperationCanceledException)
        {
            Message = "Analyse annulée.";
        }
        finally
        {
            IsScanning = false;
            _cts?.Dispose();
            _cts = null;
        }
    }
}
