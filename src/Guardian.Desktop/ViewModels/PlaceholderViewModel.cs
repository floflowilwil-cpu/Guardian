using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;

namespace Guardian.Desktop.ViewModels;

/// <summary>Page pas encore maquettée (Système, Rapports).</summary>
public sealed class PlaceholderViewModel : IPage
{
    private readonly string _titleKey;

    public PlaceholderViewModel(string title) => _titleKey = title;

    public string Title => Loc.T(_titleKey);

    public void Apply(GuardianSnapshot snapshot)
    {
    }
}
