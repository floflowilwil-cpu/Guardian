using Guardian.Desktop.Models;

namespace Guardian.Desktop.ViewModels;

/// <summary>Page de l'application : reçoit chaque nouvel état du service.</summary>
public interface IPage
{
    void Apply(GuardianSnapshot snapshot);
}
