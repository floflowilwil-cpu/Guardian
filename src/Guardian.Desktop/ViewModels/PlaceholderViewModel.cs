using Guardian.Desktop.Models;

namespace Guardian.Desktop.ViewModels;

/// <summary>Page pas encore maquettée (Système, Rapports).</summary>
public sealed class PlaceholderViewModel : IPage
{
    public PlaceholderViewModel(string title) => Title = title;

    public string Title { get; }

    public void Apply(GuardianSnapshot snapshot)
    {
    }
}
