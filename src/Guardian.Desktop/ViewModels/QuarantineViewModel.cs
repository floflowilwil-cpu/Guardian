using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;
using Guardian.Desktop.Services;

namespace Guardian.Desktop.ViewModels;

public sealed class QuarantineViewModel : ObservableObject, IPage
{
    private readonly IGuardianClient _client;
    private string _message = string.Empty;

    public QuarantineViewModel(IGuardianClient client)
    {
        _client = client;
        RestoreCommand = new AsyncRelayCommand(() => RunAsync(ids => _client.RestoreAsync(ids), Loc.T("Restauration")));
        DeleteCommand = new AsyncRelayCommand(DeleteAsync);
    }

    public ObservableCollection<QuarantineItem> Items { get; } = new();

    public ICommand RestoreCommand { get; }

    public ICommand DeleteCommand { get; }

    public string Title => $"{Loc.T("Éléments en quarantaine")} ({Items.Count})";

    public bool HasItems => Items.Count > 0;

    public string Message { get => _message; private set => Set(ref _message, value); }

    public void Apply(GuardianSnapshot s)
    {
        // Conserve les cases cochées d'un rafraîchissement à l'autre (le service renvoie de nouvelles instances).
        var checkedIds = Items.Where(i => i.IsChecked).Select(i => i.Id).ToHashSet();
        Items.Clear();
        foreach (var i in s.Quarantine)
        {
            i.IsChecked = i.IsChecked || checkedIds.Contains(i.Id);
            Items.Add(i);
        }

        Raise(nameof(Title));
        Raise(nameof(HasItems));
    }

    private async Task DeleteAsync()
    {
        var count = Items.Count(i => i.IsChecked);
        if (count == 0)
        {
            return;
        }

        // Suppression définitive : confirmation explicite (doc §9, opérations auditables et réversibles).
        var answer = MessageBox.Show(
            string.Format(Loc.T("Supprimer définitivement {0} élément(s) ? Cette action est irréversible."), count),
            "Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer == MessageBoxResult.Yes)
        {
            await RunAsync(ids => _client.DeleteAsync(ids), Loc.T("Suppression"));
        }
    }

    // Motif réel de l'échec (par exemple « La destination existe déjà : restauration refusée… »).
    private string ErrorText() =>
        string.IsNullOrWhiteSpace(_client.LastError)
            ? Loc.T("Le service n'a pas pu traiter la demande.")
            : Loc.T(_client.LastError);

    private async Task RunAsync(Func<IEnumerable<Guid>, Task<bool>> action, string label)
    {
        var ids = Items.Where(i => i.IsChecked).Select(i => i.Id).ToList();
        if (ids.Count == 0)
        {
            Message = Loc.T("Sélectionnez au moins un élément.");
            return;
        }

        var ok = await action(ids);
        Message = ok
            ? $"{label} {Loc.T("effectuée.")}"
            : ErrorText();
    }
}
